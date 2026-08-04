import admin from "firebase-admin";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const client = new DynamoDBClient({});
const ddb = DynamoDBDocumentClient.from(client);
const s3 = new S3Client({ region: "us-east-1" });

const TABLE_NAME = "detections";
const S3_BUCKET_NAME = "detection-frames-tests";

const headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "GET,OPTIONS",
};

if (
  !process.env.FIREBASE_PROJECT_ID ||
  !process.env.FIREBASE_CLIENT_EMAIL ||
  !process.env.FIREBASE_PRIVATE_KEY
) {
  throw new Error("Missing Firebase environment variables");
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
}

function getBearerToken(event) {
  const authHeader =
    event?.headers?.Authorization || event?.headers?.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  return authHeader.slice("Bearer ".length).trim();
}

async function getImageUrl(imageKey) {
  if (!imageKey) return null;
  try {
    const command = new GetObjectCommand({
      Bucket: S3_BUCKET_NAME,
      Key: imageKey,
    });
    return await getSignedUrl(s3, command, { expiresIn: 3600 });
  } catch (e) {
    console.error("Error generating signed URL:", e);
    return null;
  }
}

export const handler = async (event) => {
  if (
    event?.requestContext?.http?.method === "OPTIONS" ||
    event?.httpMethod === "OPTIONS"
  ) {
    return { statusCode: 200, headers, body: "" };
  }

  try {
    const token = getBearerToken(event);
    if (!token) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ message: "Unauthorized: missing token" }),
      };
    }

    const decodedToken = await admin.auth().verifyIdToken(token);
    const ownerUid = decodedToken.uid;

    const qs = event?.queryStringParameters ?? {};
    const limit = qs.limit ? Number(qs.limit) : 50;
    const exclusiveStartKey = qs.startKey
      ? JSON.parse(decodeURIComponent(qs.startKey))
      : undefined;

    // Consulta por el GSI de dueño: el aislamiento lo impone la clave
    // (owner_uid), no un filtro posterior, y la paginación (Limit) opera dentro
    // de los datos del propio usuario en vez de sobre la tabla completa.
    const params = {
      TableName: TABLE_NAME,
      IndexName: "owner-index",
      KeyConditionExpression: "#owner = :owner",
      FilterExpression: "#type = :type",
      ExpressionAttributeNames: { "#owner": "owner_uid", "#type": "type" },
      ExpressionAttributeValues: {
        ":owner": ownerUid,
        ":type": "event",
      },
      ScanIndexForward: false,
      Limit: limit,
      ExclusiveStartKey: exclusiveStartKey,
    };

    const result = await ddb.send(new QueryCommand(params));
    const items = result.Items ?? [];

    const itemsWithImages = await Promise.all(
      items.map(async (item) => {
        let imageUrl = null;
        try {
          const raw = JSON.parse(item.raw || "{}");
          if (raw.image_key) {
            imageUrl = await getImageUrl(raw.image_key);
          }
        } catch (e) {
          console.error("Error parsing raw:", e);
        }
        return { ...item, image_url: imageUrl };
      })
    );

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        user: {
          uid: decodedToken.uid,
          email: decodedToken.email ?? null,
        },
        items: itemsWithImages,
        lastEvaluatedKey: result.LastEvaluatedKey ?? null,
      }),
    };
  } catch (err) {
    console.error("Error:", err?.message ?? err);
    const isAuthError = err?.code?.startsWith?.("auth/") === true;
    return {
      statusCode: isAuthError ? 401 : 500,
      headers,
      body: JSON.stringify({
        message: isAuthError ? "Unauthorized" : "Error listing items",
        error: err?.message ?? "Unknown error",
      }),
    };
  }
};