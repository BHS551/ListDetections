# ListDetections

Lambda de **SkyEye** que lista las detecciones del usuario autenticado para la
consola (`/console/detections`), con la imagen de evidencia lista para mostrar.

> 📚 Contexto completo del proyecto: `docs/SKYEYE_PROJECT.md` en el repo
> `harmsDetectionLandingUi`.

## Qué hace

`GET` (con `Authorization: Bearer <ID token Firebase>`):

1. Consulta DynamoDB (`detections`) por el GSI **`owner-index`** con
   `owner_uid` = uid del token y `type = "event"`, del más reciente al más
   antiguo. Paginación con `?limit=` (default 50) y `?startKey=`
   (`lastEvaluatedKey` de la página anterior, URL-encoded).
2. Para cada evento con `image_key` en su `raw`, genera una **URL firmada de
   S3** (bucket `detection-frames-tests`, expira en 1 hora) y la devuelve como
   `image_url`.
3. Responde `{ user, items, lastEvaluatedKey }`.

El aislamiento por usuario lo impone la clave de la consulta (el GSI), no un
filtro posterior, y la paginación opera dentro de los datos del propio usuario.

## Detalles

- Credenciales de Firebase desde Secrets Manager (`heimdall/firebase`), con
  fallback a env vars para rollback.
- CORS restringido (dominio de la app + previews Vercel + localhost,
  configurable con `ALLOWED_ORIGINS`).
- Solo errores `auth/*` de firebase-admin devuelven 401.

## Variables de entorno

`FIREBASE_SECRET_ID` (default `heimdall/firebase`), `ALLOWED_ORIGINS`,
`AWS_REGION` (default `us-east-1`).

## Relacionados

- `StoreDetection` — escribe los eventos que esta Lambda lista.
- `ListDevices` — mismo patrón, para las cámaras.
