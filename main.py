"""
DigitalClerk — Recipe Service
==============================
A small, standalone service that owns the form-learning ("recipe") system:

  POST /recipe/correction   a user corrected a field -> record a vote
  GET  /recipe/rules        a user opened a form     -> return confirmed rules

It is DELIBERATELY separate from the mapping backend (main.py / Cerebras) and
from the Node backend (extraction, accounts). It shares only ONE thing with them:
the same JWT_SECRET, so the login token the extension already carries is accepted
here too — no new login system.

It connects to the SAME MySQL database as the Users table (Aiven), so the vote
table can foreign-key to real users (that FK powers "one vote per user").

WHAT IT STORES: only form structure + wiring (which field uses which data key).
NEVER a user's actual value. So a breach of this DB leaks no personal data.

Env vars required (set these on the host, e.g. Render):
  DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME   (the Aiven MySQL details)
  JWT_SECRET                                        (SAME value as your other services)
Optional:
  JWT_ALGORITHM        default HS256  (matches jsonwebtoken default)
  AUTH_ENABLED         default true   (set false only for local debugging)
  CONFIRM_THRESHOLD    default 1      (distinct users needed to confirm a rule;
                                       start at 1 for testing, raise to 3-5 for real users)
  FUZZY_ENABLED        default false  (exact fingerprint match until you turn this on)
  FUZZY_OVERLAP        default 0.8    (>=80% field-name overlap = same form, when fuzzy on)
  ALLOWED_ORIGINS      default *      (comma-separated, tighten in production)
"""

import os
import json
import uuid
import time
from typing import Optional, List, Dict, Any

import jwt                              # PyJWT
import pymysql                          # pure-python MySQL driver (simplest to deploy)
from pymysql.cursors import DictCursor
from fastapi import FastAPI, Header, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────────────────────
DB_HOST = os.environ.get("DB_HOST", "")
DB_PORT = int(os.environ.get("DB_PORT", "3306") or 3306)
DB_USER = os.environ.get("DB_USER", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME = os.environ.get("DB_NAME", "digital_clerk")

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "true").lower() != "false"

CONFIRM_THRESHOLD = int(os.environ.get("CONFIRM_THRESHOLD", "1") or 1)
# Implicit ("user left the AI's value untouched") is a WEAKER signal than an active
# correction, so it needs many more agreeing users. Separate, higher bar.
IMPLICIT_THRESHOLD = int(os.environ.get("IMPLICIT_THRESHOLD", "5") or 5)
FUZZY_ENABLED = os.environ.get("FUZZY_ENABLED", "false").lower() == "true"
FUZZY_OVERLAP = float(os.environ.get("FUZZY_OVERLAP", "0.8") or 0.8)

ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "*").split(",")]


app = FastAPI(title="DigitalClerk Recipe Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
#  DB  — a fresh short-lived connection per request (simple + safe for low volume;
#        swap to a pool later if traffic grows). Aiven requires SSL, so ssl is on.
# ─────────────────────────────────────────────────────────────────────────────
def get_db():
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=DictCursor,
        autocommit=True,
        ssl={"ssl": {}},          # Aiven mandates TLS; empty dict = use TLS, don't pin CA
        connect_timeout=10,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  AUTH  — verify the same JWT the Node backend issues at login. Pure signature
#          math against the shared JWT_SECRET; no DB call. The user id inside the
#          token is what powers "one vote per user".
# ─────────────────────────────────────────────────────────────────────────────
def verify_jwt(authorization: str = Header(None)) -> dict:
    if not AUTH_ENABLED:
        return {"sub": "auth-disabled"}
    if not JWT_SECRET:
        # fail closed — never run unauthenticated by accident
        raise HTTPException(status_code=500, detail="Auth not configured on server")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired — please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def user_id_from_claims(claims: dict) -> str:
    """
    Pull the user id out of the token. Node's jsonwebtoken payloads vary, so we
    check the common shapes. Adjust the key here if your token uses a different one.
    """
    for k in ("id", "userId", "user_id", "sub"):
        v = claims.get(k)
        if v:
            return str(v)
    # some backends nest it under "user"
    u = claims.get("user")
    if isinstance(u, dict):
        for k in ("id", "userId", "_id"):
            if u.get(k):
                return str(u[k])
    raise HTTPException(status_code=401, detail="Token has no user id")


# ─────────────────────────────────────────────────────────────────────────────
#  MODELS
# ─────────────────────────────────────────────────────────────────────────────
class CorrectionIn(BaseModel):
    site_host: str
    path: str
    form_group: Optional[str] = None      # host+path; groups all tabs of one form
    field_fingerprint: str
    field_names: List[str] = []
    field_key: str
    filled_source_key: Optional[str] = None
    correct_source_key: str
    action: Optional[str] = "type"
    match_type: Optional[str] = "single"
    signal_type: Optional[str] = "correction"   # 'correction' (strong) | 'implicit' (weak)


# ─────────────────────────────────────────────────────────────────────────────
#  POST /recipe/correction  — record a vote, then try to promote the rule
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/recipe/correction")
def post_correction(body: CorrectionIn, claims: dict = Depends(verify_jwt)):
    uid = user_id_from_claims(claims)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # 1) Upsert this user's vote. UNIQUE(fingerprint, field_key, user_id)
            #    means a repeat correction by the same user updates, never duplicates —
            #    so one person can't inflate the count.
            # form_group falls back to host+path if the extension didn't send it,
            # so it's always populated consistently.
            fg = body.form_group or f"{body.site_host}{body.path}"
            sig_type = (body.signal_type or "correction").lower()
            if sig_type not in ("correction", "implicit"):
                sig_type = "correction"

            cur.execute(
                """
                INSERT INTO recipe_corrections
                    (id, site_host, path, form_group, field_fingerprint, field_key,
                     filled_source_key, correct_source_key, action, user_id, match_type, signal_type)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    correct_source_key = VALUES(correct_source_key),
                    filled_source_key  = VALUES(filled_source_key),
                    form_group         = VALUES(form_group),
                    action             = VALUES(action),
                    match_type         = VALUES(match_type),
                    signal_type        = VALUES(signal_type),
                    created_at         = CURRENT_TIMESTAMP
                """,
                (str(uuid.uuid4()), body.site_host, body.path, fg, body.field_fingerprint,
                 body.field_key, body.filled_source_key, body.correct_source_key,
                 body.action or "type", uid, body.match_type or "single", sig_type),
            )

            # 2) Decide if this field now has a confirmable rule. Corrections and
            #    implicit votes are counted in SEPARATE buckets with DIFFERENT bars:
            #      - corrections (strong)  -> CONFIRM_THRESHOLD  (e.g. 1)
            #      - implicit  (weak)      -> IMPLICIT_THRESHOLD (e.g. 5)
            #    A CORRECTION ALWAYS WINS over implicit: if any correction bucket meets
            #    its bar, it decides the rule and any implicit-derived rule is overwritten.
            #    Silence never beats an active correction.
            cur.execute(
                """
                SELECT correct_source_key, signal_type,
                       COUNT(DISTINCT user_id) AS votes
                FROM recipe_corrections
                WHERE field_fingerprint = %s
                  AND field_key = %s
                  AND is_test_account = 0
                GROUP BY correct_source_key, signal_type
                """,
                (body.field_fingerprint, body.field_key),
            )
            rows = cur.fetchall()

            # Find the best correction candidate and the best implicit candidate.
            best_corr = None   # (key, votes)
            best_impl = None
            for r in rows:
                key, st, votes = r["correct_source_key"], r["signal_type"], int(r["votes"])
                if st == "correction":
                    if not best_corr or votes > best_corr[1]:
                        best_corr = (key, votes)
                else:
                    if not best_impl or votes > best_impl[1]:
                        best_impl = (key, votes)

            # Correction wins if it meets its (low) bar; else implicit if it meets its
            # (high) bar. This ordering is what makes a correction override silence.
            chosen_key = None
            chosen_votes = 0
            chosen_via = None
            if best_corr and best_corr[1] >= CONFIRM_THRESHOLD:
                chosen_key, chosen_votes, chosen_via = best_corr[0], best_corr[1], "correction"
            elif best_impl and best_impl[1] >= IMPLICIT_THRESHOLD:
                chosen_key, chosen_votes, chosen_via = best_impl[0], best_impl[1], "implicit"

            promoted = False
            if chosen_key:
                cur.execute(
                    """
                    INSERT INTO form_recipes
                        (id, site_host, path, form_group, field_fingerprint, field_names,
                         field_key, source_key, action, status, confirm_count, last_confirmed_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'confirmed',%s,CURRENT_TIMESTAMP)
                    ON DUPLICATE KEY UPDATE
                        source_key        = VALUES(source_key),
                        field_names       = VALUES(field_names),
                        form_group        = VALUES(form_group),
                        status            = 'confirmed',
                        confirm_count     = VALUES(confirm_count),
                        last_confirmed_at = CURRENT_TIMESTAMP,
                        updated_at        = CURRENT_TIMESTAMP
                    """,
                    (str(uuid.uuid4()), body.site_host, body.path, fg, body.field_fingerprint,
                     json.dumps(body.field_names or []), body.field_key,
                     chosen_key, body.action or "type", int(chosen_votes)),
                )
                promoted = True

        return {"success": True, "promoted": promoted, "via": chosen_via}
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
#  GET /recipe/rules  — return confirmed rules for a form
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/recipe/rules")
def get_rules(
    site_host: str = Query(""),
    path: str = Query(""),
    field_fingerprint: str = Query(""),
    field_names: str = Query(""),                 # comma-separated
    claims: dict = Depends(verify_jwt),
):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Fast path: exact fingerprint match (covers the overwhelming majority).
            cur.execute(
                """
                SELECT field_key, source_key
                FROM form_recipes
                WHERE field_fingerprint = %s AND status = 'confirmed'
                """,
                (field_fingerprint,),
            )
            rows = cur.fetchall()

            # Optional fuzzy fallback: if nothing matched exactly and fuzzy is on,
            # compare the incoming field-name set against stored ones on the same
            # host+path, and accept forms with >= FUZZY_OVERLAP overlap.
            if not rows and FUZZY_ENABLED and field_names:
                incoming = set(n for n in field_names.split(",") if n)
                if incoming:
                    # Filter to the SAME form family first (form_group = host+path),
                    # then compare field-name sets within it. This keeps different tabs
                    # of the same URL apart while tolerating fingerprint drift on one tab.
                    fg = f"{site_host}{path}"
                    cur.execute(
                        """
                        SELECT field_key, source_key, field_names
                        FROM form_recipes
                        WHERE form_group = %s AND status = 'confirmed'
                        """,
                        (fg,),
                    )
                    candidates = cur.fetchall()
                    picked: Dict[str, str] = {}
                    for c in candidates:
                        try:
                            stored = set(json.loads(c["field_names"] or "[]"))
                        except Exception:
                            stored = set()
                        if not stored:
                            continue
                        overlap = len(incoming & stored) / max(len(incoming | stored), 1)
                        if overlap >= FUZZY_OVERLAP:
                            picked[c["field_key"]] = c["source_key"]
                    return {"success": True, "rules": picked, "match": "fuzzy"}

            rules = {r["field_key"]: r["source_key"] for r in rows}
            return {"success": True, "rules": rules, "match": "exact"}
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
#  HEALTH / DEBUG  (no secrets exposed)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"service": "digitalclerk-recipe", "ok": True}


@app.get("/debug")
def debug():
    db_ok = False
    err = None
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT 1 AS ok")
            db_ok = cur.fetchone()["ok"] == 1
        conn.close()
    except Exception as e:
        err = str(e)[:200]
    return {
        "auth_enabled": AUTH_ENABLED,
        "jwt_secret_set": bool(JWT_SECRET),
        "jwt_algorithm": JWT_ALGORITHM,
        "db_connected": db_ok,
        "db_error": err,
        "confirm_threshold": CONFIRM_THRESHOLD,
        "implicit_threshold": IMPLICIT_THRESHOLD,
        "fuzzy_enabled": FUZZY_ENABLED,
    }
