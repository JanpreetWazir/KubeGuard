from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import sqlite3
import traceback

app = FastAPI(title="KubeGuard Vulnerable Demo API")

# ==========================================
# VULNERABILITY 1: Hardcoded Secrets (CWE-798)
# ==========================================
# WHY IT'S BAD: Secrets should NEVER be in source code. 
# If this code is pushed to GitHub, attackers can extract the key and forge JWT tokens.
# PROPER FIX: Load from environment variables or a Secret Manager.
JWT_SECRET = "super_secret_dev_key_12345"


# Database setup (Dummy data)
def setup_db():
    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, secret_data TEXT)')
    c.execute('DELETE FROM users') # clear old data
    c.execute("INSERT INTO users (username, password, role, secret_data) VALUES ('admin', 'admin123', 'admin', 'Admin Top Secret Info')")
    c.execute("INSERT INTO users (username, password, role, secret_data) VALUES ('janpreet', 'password123', 'user', 'Janpreet personal phone number')")
    conn.commit()
    conn.close()

setup_db()


# ==========================================
# VULNERABILITY 2: SQL Injection (SQLi) (CWE-89)
# ==========================================
# WHY IT'S BAD: We are using python f-strings to concatenate user input directly into the SQL query.
# An attacker can send a username like: admin' OR '1'='1
# This alters the query logic to return all users.
# PROPER FIX: Use parameterized queries (e.g., c.execute("SELECT * FROM users WHERE username = ?", (username,)))
@app.get("/api/users/search")
def search_users(username: str):
    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    
    # DANGEROUS: String formatting in SQL query
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    c.execute(query)
    
    users = c.fetchall()
    conn.close()
    return {"query_executed": query, "results": users}


# ==========================================
# VULNERABILITY 3: Insecure Direct Object Reference (IDOR / BOLA) (CWE-639)
# ==========================================
# WHY IT'S BAD: The API looks up a user's secret data based purely on the ID provided in the URL.
# There is no check to see if the person making the request is ACTUALLY the user who owns that ID.
# Anyone can iterate /api/profile/1, /api/profile/2 and steal all data.
# PROPER FIX: Verify the session/token belongs to the requested ID before returning data.
@app.get("/api/profile/{user_id}")
def get_profile(user_id: int):
    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    
    c.execute("SELECT username, secret_data FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    
    if user:
        return {"username": user[0], "sensitive_data": user[1]}
    raise HTTPException(status_code=404, detail="User not found")


# ==========================================
# VULNERABILITY 4 & 5: Missing Rate Limiting & Verbose Errors (CWE-307 & CWE-209)
# ==========================================
# WHY IT'S BAD (Rate Limiting): An attacker can run a script to try 10,000 passwords a minute (Brute Force).
# PROPER FIX: Implement IP-based or account-based rate limiting (e.g., max 5 attempts per minute).
#
# WHY IT'S BAD (Verbose Errors): If something breaks, we return the raw Python Exception to the user.
# This leaks internal infrastructure details (like table names or file paths).
# PROPER FIX: Catch the exception, log it internally, and return a generic "500 Internal Server Error" to the user.
class LoginModel(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def login(credentials: LoginModel):
    try:
        conn = sqlite3.connect('demo.db')
        c = conn.cursor()
        
        # Checking login (Simulated vulnerability if DB fails)
        query = f"SELECT * FROM users WHERE username = '{credentials.username}' AND password = '{credentials.password}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()
        
        if user:
            return {"message": "Login successful", "token": JWT_SECRET}
        return {"message": "Invalid credentials"}
        
    except Exception as e:
        # DANGEROUS: Leaking backend stack trace to the frontend client
        error_details = traceback.format_exc()
        raise HTTPException(status_code=500, detail=f"Database Error: {str(e)} \n\n Traceback: {error_details}")
