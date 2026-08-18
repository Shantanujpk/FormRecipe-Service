# DigitalClerk Recipe Service

A small standalone service for the form-learning ("recipe") system.
Separate from the mapping backend and the Node backend — it shares only the
JWT secret and the MySQL database.

## Endpoints

- `POST /recipe/correction` — record a user's correction as a vote; auto-confirms
  a rule once enough distinct users agree.
- `GET  /recipe/rules?site_host=&path=&field_fingerprint=&field_names=a,b,c`
  — return confirmed field→key rules for a form.
- `GET  /debug` — health: shows whether the DB is reachable and the JWT secret is set
  (never exposes the secret).

Both recipe endpoints require `Authorization: Bearer <token>` — the same login
token the extension already carries.

## Environment variables

Required:
```
DB_HOST=mysql-878c923-patilsidharth6-6868.h.aivencloud.com
DB_PORT=25850
DB_USER=avnadmin
DB_PASSWORD=<your aiven password>
DB_NAME=digital_clerk
JWT_SECRET=<SAME value as your other services>
```

Optional (sensible defaults):
```
JWT_ALGORITHM=HS256        # matches jsonwebtoken default
AUTH_ENABLED=true
CONFIRM_THRESHOLD=1        # raise to 3-5 once you have real users
FUZZY_ENABLED=false        # exact fingerprint match until turned on
FUZZY_OVERLAP=0.8
ALLOWED_ORIGINS=*          # tighten in production
```

## Run locally
```
pip install -r requirements.txt
# set the env vars above (export or a .env loaded by your shell)
uvicorn main:app --reload --port 8000
# then open http://localhost:8000/debug
```

## Deploy on Render
1. New → Web Service → connect this repo/folder.
2. Build command:  `pip install -r requirements.txt`
3. Start command:  `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Add all the env vars above in the Render dashboard.
5. Deploy, then open `https://<your-service>.onrender.com/debug` and confirm:
   `db_connected: true`, `jwt_secret_set: true`.

## After deploy — wire the extension
In `service-worker.js`:
- set `RECIPE_URL` to this service's base URL
- set `RECIPE_BACKEND = true`
That's the only extension change.
