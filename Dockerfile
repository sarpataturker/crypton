# CRYPTON API - FINAL WORKING VERSION
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install ALL required Python packages in one go
RUN pip install --no-cache-dir \
    fastapi==0.104.1 \
    uvicorn[standard]==0.24.0 \
    pydantic==2.5.2 \
    python-jose[cryptography]==3.3.0 \
    python-multipart==0.0.6 \
    cryptography==41.0.7 \
    bcrypt==4.1.2 \
    argon2-cffi==23.1.0 \
    pynacl==1.5.0 \
    passlib[bcrypt,argon2]==1.7.4 \
    colorama==0.4.6 \
    httpx==0.25.2 \
    requests==2.31.0 \
    pyjwt==2.8.0

# Copy application files
COPY api_server.py .
COPY main.py .

# Create non-root user
RUN useradd -m -u 1000 crypton && chown -R crypton:crypton /app
USER crypton

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Environment variables
ENV PYTHONUNBUFFERED=1

# Start command
CMD ["python", "-m", "uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]