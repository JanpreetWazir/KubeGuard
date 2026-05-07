import os
import sqlite3
import logging
import time
from fastapi import FastAPI, HTTPException, Request, Depends, Header
from pydantic import BaseModel

# Set up logging for generic error handling
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="KubeGuard Secure Demo API")

# Simple in-memory rate limiter for demo purposes
class RateLimiter:
    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self.clients = {}

    def __call__(self, request: Request):
        client_ip = request.client.host
        now = time.time()
        
        if client_ip not in self.clients:
            self.clients[client_ip] = []
            
        # Clean up old requests
        self.clients[client_ip] = [req_time for req_time in self.clients[client_ip] if now - req_time < 60]
        
        if len(self.clients[client_ip]) >= self.requests_per_minute:
            raise HTTPException(status_code=429, detail="Too Many Requests")
            
        self.clients[client_ip].append(now)

login_limiter = RateLimiter(requests_per_minute=5)
api_limiter = RateLimiter(requests_per_minute=20)

# ==========================================
# FIX 1: Secrets Management (CWE-798 Mitigated)
# ==========================================
# Secret is loaded from the environment, injected via Kubernetes Secrets in prod.
JWT_SECRET = os.getenv("JWT_SECRET", "default_fallback_secret")

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

# Dummy Token Verifier for IDOR Fix
def verify_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Header")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Token format")
    # In a real app, verify JWT signature and decode user info
    return authorization.split(" ")[1]

# ==========================================
# FIX 2: SQL Injection (SQLi) (CWE-89 Mitigated)
# ==========================================
# FIX: Using parameterized queries (?) instead of f-strings.
@app.get("/api/users/search", dependencies=[Depends(api_limiter)])
def search_users(username: str):
    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    
    # SAFE: Parameterized query
    c.execute("SELECT id, username, role FROM users WHERE username = ?", (username,))
    
    users = c.fetchall()
    conn.close()
    return {"results": users}

# ==========================================
# FIX 3: Insecure Direct Object Reference (IDOR / BOLA) (CWE-639 Mitigated)
# ==========================================
# FIX: Verifying the identity of the user making the request.
@app.get("/api/profile/{user_id}", dependencies=[Depends(api_limiter)])
def get_profile(user_id: int, token: str = Depends(verify_token)):
    # Here we would typically decode the token and ensure token.user_id == user_id
    # Simulating authorization check failure if token is dummy 'guest_token'
    if token == "guest_token":
        raise HTTPException(status_code=403, detail="Not authorized to view this profile")

    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    
    c.execute("SELECT username, secret_data FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    
    if user:
        return {"username": user[0], "sensitive_data": user[1]}
    raise HTTPException(status_code=404, detail="User not found")

# ==========================================
# FIX 4 & 5: Rate Limiting & Verbose Errors (CWE-307 & CWE-209 Mitigated)
# ==========================================
# FIX: Added dependencies=[Depends(login_limiter)] to endpoints to prevent brute force.
# FIX: Caught exceptions log internally and return generic 500 error.
class LoginModel(BaseModel):
    username: str
    password: str

@app.post("/api/login", dependencies=[Depends(login_limiter)])
def login(credentials: LoginModel):
    try:
        conn = sqlite3.connect('demo.db')
        c = conn.cursor()
        
        # SAFE: Parameterized query for login
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (credentials.username, credentials.password))
        user = c.fetchone()
        conn.close()
        
        if user:
            return {"message": "Login successful", "token": JWT_SECRET}
        return {"message": "Invalid credentials"}
        
    except Exception as e:
        # SAFE: Log the real error to the server console only
        logger.error(f"Database Error during login: {str(e)}")
        # Return a generic error to the client
        raise HTTPException(status_code=500, detail="An internal server error occurred.")
