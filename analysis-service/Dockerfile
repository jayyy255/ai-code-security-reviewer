FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies: git, curl, tar, ca-certificates, clamav
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    tar \
    ca-certificates \
    clamav \
    clamav-freshclam \
    && rm -rf /var/lib/apt/lists/*

# Install official Gitleaks binary
ARG GITLEAKS_VERSION=8.24.0
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GL_ARCH="x64"; \
    elif [ "$ARCH" = "aarch64" ]; then GL_ARCH="arm64"; \
    else GL_ARCH="x64"; fi && \
    curl -sSL -o /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm /tmp/gitleaks.tar.gz

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code and rules
COPY . .

EXPOSE 8000

ENV PORT=8000
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
