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

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID || "login-69a8a",
      clientEmail:
        process.env.FIREBASE_CLIENT_EMAIL ||
        "firebase-adminsdk-fbsvc@login-69a8a.iam.gserviceaccount.com",
      privateKey: (
        process.env.FIREBASE_PRIVATE_KEY ||
        "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
      ).replace(/\\n/g, "\n"),
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
  console.log("Incoming event:", JSON.stringify(event));

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

    const params = {
      TableName: TABLE_NAME,
      KeyConditionExpression: "#pk = :pk",
      FilterExpression: "owner_uid = :ownerUid",
      ExpressionAttributeNames: { "#pk": "type" },
      ExpressionAttributeValues: {
        ":pk": "event",
        ":ownerUid": ownerUid,
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
    console.error("Error:", err);
    const isAuthError =
      err?.code?.startsWith?.("auth/") ||
      err?.message?.toLowerCase?.().includes("token");
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