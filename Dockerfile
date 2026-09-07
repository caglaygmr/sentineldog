FROM python:3.12-slim-bookworm

LABEL maintainer="Cagla Yagmur Yaylaci"
LABEL description="SentinelDog: Linux Security Watchdog, Rootkit Cross-View Detector & Log Sentinel"

# Install standard Linux diagnostics and procps
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps \
    iproute2 \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY requirements.txt pyproject.toml /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and configurations
COPY src/ /app/src/
COPY config/ /app/config/
COPY tests/ /app/tests/
COPY scripts/ /app/scripts/

# Install sentineldog in editable/system mode
RUN pip install --no-cache-dir --no-build-isolation -e .

# Create log & data directories
RUN mkdir -p /app/logs /app/data

# Default command runs a diagnostic scan
ENTRYPOINT ["sentineldog"]
CMD ["scan"]
