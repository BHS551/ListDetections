# ListDetections

The AWS Lambda that returns a user's detection events for
[SkyEye](https://www.skyeyeprotection.com/), each with a temporary link to the
frame that triggered it.

## The problem it solves

A detection is only useful with its evidence. The console needs to show the
captured frame next to the event — but those frames are security footage of the
customer's own premises, so the bucket cannot be public, and the URL cannot be
permanent.

This function joins the two halves: it reads the event metadata from DynamoDB
and mints a short-lived presigned S3 URL for each frame, so the browser can
render images from a private bucket without ever holding AWS credentials.

## How it works

```
GET /?limit=50&startKey=<encoded>      Authorization: Bearer <Firebase ID token>
   │
   ▼
verifyIdToken()  ──► ownerUid   (401 if missing or invalid)
   │
   ▼
Query `detections`
   IndexName        owner-index
   KeyCondition     owner_uid = <uid from the token>    ← isolation by key
   Filter           type = "event"
   ScanIndexForward false                               ← newest first
   Limit / ExclusiveStartKey
   │
   ▼
for each row, in parallel:
   parse raw JSON  ──►  image_key present?
                          └─► getSignedUrl(GetObject, expiresIn: 3600)
   │
   ▼
200 { user, items: [ { …event, image_url }, … ], lastEvaluatedKey }
```

## Key technical decisions

**Isolation comes from the key, not a filter.** The query is keyed on
`owner_uid` through the `owner-index` GSI, so another user's events are not
merely filtered out — they are never read. A `Scan`-plus-filter version would
put every customer's data one bug away from exposure, cost every user the whole
table, and break pagination, because DynamoDB applies `Limit` before the
filter.

**Presigned URLs expire in an hour.** Long enough to browse a session, short
enough that a copied link is not a permanent handle on someone's footage. They
are generated per request, so the stored data contains only the S3 key.

**A missing or unreadable frame does not fail the request.** URL generation is
wrapped per item and returns `null` on error, so `image_url: null` renders a
detection without its picture rather than returning a 500 for the whole page.
Frames expire from S3 on a shorter schedule than the events themselves, so an
old event legitimately has no image.

**Signing happens in parallel.** The items are mapped through `Promise.all`, so
a page of 50 costs roughly one signing round rather than 50 sequential ones.

**Pagination is opaque and complete.** `lastEvaluatedKey` is returned as-is and
accepted back as a URL-encoded `startKey`, so the client pages without knowing
the table's key structure.

**Only `auth/*` errors are 401.** Everything else is a 500.

## API

```http
GET /?limit=50
GET /?limit=50&startKey=%7B%22id%22%3A…%7D
Authorization: Bearer <Firebase ID token>
```

```json
{
  "user": { "uid": "…" },
  "items": [
    {
      "type": "event",
      "id": "2026-08-05T12:31:44.201Z-a91f3d",
      "created_at": "2026-08-05T12:31:44.201Z",
      "owner_uid": "…",
      "raw": "{\"camera\":\"entrance\",\"label\":\"caidas\",\"image_key\":\"cameras/…\"}",
      "image_url": "https://detection-frames-tests.s3.amazonaws.com/…?X-Amz-Signature=…"
    }
  ],
  "lastEvaluatedKey": null
}
```

`limit` defaults to 50. `OPTIONS` returns 200 with the CORS headers.

Events are written by
[StoreDetection](https://github.com/BHS551/StoreDetection); the frames are
uploaded by the detection worker,
[harmsDetection](https://github.com/BHS551/harmsDetection).

## Deploying

Node.js 18+ on AWS Lambda behind API Gateway, handler `index.mjs`.

```bash
npm install firebase-admin @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb \
            @aws-sdk/client-s3 @aws-sdk/s3-request-presigner \
            @aws-sdk/client-secrets-manager
zip -r function.zip . && aws lambda update-function-code \
  --function-name listDetections --zip-file fileb://function.zip
```

Requires the `detections` table with an `owner-index` GSI on `owner_uid` and
the `detection-frames-tests` bucket. The execution role needs `dynamodb:Query`
on the index, `s3:GetObject` on the bucket, and `secretsmanager:GetSecretValue`
on the Firebase secret.

| Variable | Default | Meaning |
|---|---|---|
| `FIREBASE_SECRET_ID` | `heimdall/firebase` | Service account secret id |
| `ALLOWED_ORIGINS` | — | Comma-separated CORS allow-list |
