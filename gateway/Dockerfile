FROM python:3.11-slim

WORKDIR /app

# Prevent Python from writing .pyc and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Install dependencies from root requirements.txt
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application modules and configurations
COPY gateway /app/gateway
COPY ml /app/ml
COPY agents /app/agents
COPY config /app/config
COPY events /app/events

EXPOSE 8000

CMD ["uvicorn", "gateway.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
