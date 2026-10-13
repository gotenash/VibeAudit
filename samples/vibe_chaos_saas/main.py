# Vibe Chaos SaaS - Example of typical vibe-coded project

import os
import sys
import sqlite3
import easy_gpt4  # Hallucinated dependency!
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Vibe flaw 1: Hardcoded OpenAI Secret Key
OPENAI_API_KEY = "sk-proj-99887766554433221100aabbccddeeff"

# Vibe flaw 2: Wildcard CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to database
conn = sqlite3.connect("users.db")

@app.get("/search")
def search_user(username: str):
    cursor = conn.cursor()
    # Vibe flaw 3: Direct SQL string interpolation
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

@app.post("/calculate")
def dynamic_calc(formula: str):
    try:
        # Vibe flaw 4: Dangerous eval usage
        result = eval(formula)
        return {"result": result}
    except Exception:
        # Vibe flaw 5: Silent exception swallowing
        pass

@app.post("/sync")
def sync_data():
    # Vibe flaw 6: Pass-only placeholder function
    pass
