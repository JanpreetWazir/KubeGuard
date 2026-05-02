import os
import hashlib

# 1. Command Injection (Bandit and Semgrep should catch this)
def run_user_input(user_command):
    os.system(user_command) 

# 2. Weak Cryptography (Bandit should catch this)
def insecure_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

# 3. Hardcoded Secret (Gitleaks/Semgrep should catch this)
ADMIN_API_KEY = "kubeguard_1234567890abcdef1234567890abcdef"
