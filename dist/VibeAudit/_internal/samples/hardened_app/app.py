"""
Hardened Application - High quality, clean architecture sample.
"""
import os
import sqlite3
import logging
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Clean secret handling via environment variable
API_KEY = os.getenv("APP_API_KEY", "")

def get_db_connection():
    return sqlite3.connect("secure.db")

@app.route("/user/<int:user_id>", methods=["GET"])
def get_user(user_id: int):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Parameterized SQL query
            cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"error": "User not found"}), 404
            return jsonify({"id": user[0], "username": user[1], "email": user[2]})
    except sqlite3.DatabaseError as e:
        logger.error(f"Database error during get_user: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
