# We use 'slim' to reduce the attack surface (fewer tools for a hacker to use)
FROM python:3.10-slim

# Step 1: Set a working directory
WORKDIR /app

# Step 2: Copy your requirements
COPY requirements.txt .

# Step 3: Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Step 4: Copy the rest of your controller code
COPY . .

# This is just a placeholder command for now
CMD ["python", "--version"]
