FROM python:3.10-slim

# Install system dependencies for raw packet sniffing
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Upgrade pip and install core runtime dependencies
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir \
    scapy \
    loguru \
    pyyaml \
    numpy<2.0 \
    pandas \
    stable-baselines3 \
    psutil

# Copy your root-level application layout into the workspace
COPY . .

# Run the live firewall engine by default inside the container segment
CMD ["python3", "main.py", "--mode", "firewall"]
