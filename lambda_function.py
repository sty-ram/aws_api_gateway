import json

import pymysql
import hashlib

DB_HOST = "database-1.c0jechc63vd8.us-west-1.rds.amazonaws.com"
DB_USER = "admin"
DB_PASSWORD = "stylopay2026"
DB_NAME = "COMPLIANCE_RAM"

def get_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def lambda_handler(event, context):
    path = event.get("rawPath", "")
    method = event.get("requestContext", {}).get("http", {}).get("method", "")

    # ---------- HEALTH ----------
    if path == "/health" and method == "GET":
        return response(200, {"status": "ok"})

    # Parse body safely
    body = {}
    if event.get("body"):
        body = json.loads(event["body"])

    # ---------- SIGNUP ----------
    if path == "/signup" and method == "POST":
        username = body.get("username")
        password = body.get("password")

        if not username or not password:
            return response(400, {"error": "username and password required"})

        try:
            conn = get_connection()
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                    (username, hash_password(password))
                )
                conn.commit()
            return response(201, {"message": "User created"})
        except pymysql.err.IntegrityError:
            return response(409, {"error": "User already exists"})
        except Exception as e:
            return response(500, {"error": str(e)})

    # ---------- SIGNIN ----------
    if path == "/signin" and method == "POST":
        username = body.get("username")
        password = body.get("password")

        if not username or not password:
            return response(400, {"error": "username and password required"})

        try:
            conn = get_connection()
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT password_hash FROM users WHERE username=%s",
                    (username,)
                )
                user = cursor.fetchone()

            if not user:
                return response(401, {"error": "Invalid credentials"})

            if user["password_hash"] != hash_password(password):
                return response(401, {"error": "Invalid credentials"})

            return response(200, {"message": "Login successful"})
        except Exception as e:
            return response(500, {"error": str(e)})

    return response(404, {"error": "Not found"})

def response(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        },
        "body": json.dumps(body)
    }
