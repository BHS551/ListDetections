import admin from "firebase-admin";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const client = new DynamoDBClient({});
const ddb = DynamoDBDocumentClient.from(client);
const s3 = new S3Client({ region: "us-east-1" });

const TABLE_NAME = "detections";
const S3_BUCKET_NAME = "detection-frames-tests";
const MAX_LIMIT = 200;
const DEFAULT_LIMIT = 50;

const headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "GET,OPTIONS",
};

// firebase-admin: la credencial se lee de Secrets Manager (heimdall/firebase)
// en lugar de variables de entorno. Cae a las env vars solo si el secreto no
// está disponible, para permitir un rollback seguro.
const secretsClient = new SecretsManagerClient({
  region: process.env.AWS_REGION || "us-east-1",
});
const FIREBASE_SECRET_ID = process.env.FIREBASE_SECRET_ID || "heimdall/firebase";

let firebaseReady = null;
function ensureFirebase() {
  if (!firebaseReady) {
    firebaseReady = (async () => {
      if (admin.apps.length) return;
      let sa = null;
      try {
        const res = await secretsClient.send(
          new GetSecretValueCommand({ SecretId: FIREBASE_SECRET_ID })
        );
        const secret = JSON.parse(res.SecretString);
        sa = secret.service_account || secret;
      } catch (e) {
        if (!process.env.FIREBASE_PRIVATE_KEY) throw e;
      }
      const credential = sa
        ? admin.credential.cert({
            projectId: sa.project_id,
            clientEmail: sa.client_email,
            privateKey: sa.private_key,
          })
        : admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
          });
      admin.initializeApp({ credential });
    })();
  }
  return firebaseReady;
}

// CORS: refleja el origen solo si está permitido (dominio de la app + previews
// de Vercel + localhost). Configurable con ALLOWED_ORIGINS (lista separada por
// comas). Antes se enviaba "*" a cualquier origen.
const STATIC_ALLOWED = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const DEFAULT_ORIGIN =
  STATIC_ALLOWED[0] || "https://harms-detection-landing-ui-seven.vercel.app";
function allowOrigin(event) {
  const origin =
    event?.headers?.origin || event?.headers?.Origin || "";
  const ok =
    STATIC_ALLOWED.includes(origin) ||
    /^https:\/\/([a-z0-9-]+\.)*vercel\.app$/i.test(origin) ||
    /^http:\/\/localhost(:\d+)?$/i.test(origin);
  return ok ? origin : DEFAULT_ORIGIN;
}

function getBearerToken(event) {
  const authHeader =
    event?.headers?.Authorization || event?.headers?.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  return authHeader.slice("Bearer ".length).trim();
}

// Acota `limit` a un rango razonable: sin tope, un cliente podía pedir un
// Query arbitrariamente grande (costo/latencia); NaN o valores negativos
// caían silenciosamente en un Query mal formado.
function parseLimit(raw) {
  const n = Number(raw);
  if (!raw || !Number.isFinite(n) || n <= 0) return DEFAULT_LIMIT;
  return Math.min(Math.floor(n), MAX_LIMIT);
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
  headers["Access-Control-Allow-Origin"] = allowOrigin(event);
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

    await ensureFirebase();
    const decodedToken = await admin.auth().verifyIdToken(token);
    const ownerUid = decodedToken.uid;

    const qs = event?.queryStringParameters ?? {};
    const limit = parseLimit(qs.limit);
    let exclusiveStartKey;
    if (qs.startKey) {
      try {
        exclusiveStartKey = JSON.parse(decodeURIComponent(qs.startKey));
      } catch (e) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ message: "Invalid startKey" }),
        };
      }
    }

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
