# =============================================================================
# MONOLITH RED TEAM FRAMEWORK v1.0.0
# Quantum-Resistant Edition (Endgame Release)
# =============================================================================
#
# Features:
# - Full EDR Evasion Suite (AMSI, ETW, Sleep Obfuscation, Sleepmask)
# - Process Injection Masterclass (Ghosting, Early Bird, Module Stomping)
# - Syscall Obfuscation Monster (Indirect, Fresh SSN, GAN Mutation)
# - Persistence God Mode (Multi-chain, BITS, COM, WMI, Registry)
# - Kerberos Relay Ninja (NTLM Relay, Unconstrained Delegation)
# - ML Evasion Booster (GAN Signatures, Behavioral Analysis)
# - Cloud Pivot Suite (Azure, AWS, GCP lateral movement)
# - Behavioral Mimicry (Human-like EDR bypass)
# - Quantum-Resistant Crypto (Kyber, Dilithium, Hybrid Mode)
#
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="CyberPunk Framework"
LABEL version="1.0.0"
LABEL description="Monolith Red Team Framework - Quantum-Resistant Edition"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt requirements_extra.txt /app/
RUN python -m pip install --no-cache-dir --upgrade pip && \
    python -m pip install --no-cache-dir -r requirements.txt -r requirements_extra.txt

# Copy application code
COPY . /app

# Create necessary directories
RUN mkdir -p /app/reports /app/logs /app/data

# Environment variables
ENV MONOLITH_HOST=0.0.0.0
ENV MONOLITH_PORT=5000
ENV MONOLITH_VERSION=1.0.0
ENV PYTHONUNBUFFERED=1

# Expose ports
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Default command
CMD ["python3", "cyber.py"]
