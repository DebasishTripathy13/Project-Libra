# ProjectLibra - Agentic AI-Driven Security Platform
# Multi-stage build for optimized container size

# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim as production

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    procps \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash libra

# Copy Python packages from builder
COPY --from=builder /root/.local /home/libra/.local

# Copy application code
COPY --chown=libra:libra . .

# Set environment
ENV PATH=/home/libra/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV LIBRA_ENV=production
ENV LIBRA_LOG_LEVEL=INFO

# Create directories for data persistence
RUN mkdir -p /app/data /app/logs /app/models \
    && chown -R libra:libra /app

# Switch to non-root user
USER libra

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default command - run the main application
CMD ["python", "-m", "src.main"]
