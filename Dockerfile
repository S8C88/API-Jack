FROM python:3.11-slim

LABEL org="Sideways 8 Creations"
LABEL description="API-Jack — REST API Security Scanner"
LABEL version="1.0.0"

WORKDIR /app

# Create non-root user
RUN addgroup --system s8c88 && adduser --system --ingroup s8c88 s8c88

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY apijack.py endpoints.json ./
COPY examples/ ./examples/

# Switch to non-root user
USER s8c88

ENTRYPOINT ["python", "apijack.py"]
CMD ["--help"]
