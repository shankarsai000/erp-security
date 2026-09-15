FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir fastapi uvicorn pydantic

COPY fake_erp.py /app/fake_erp.py

EXPOSE 8001

CMD ["uvicorn", "fake_erp:fake_erp", "--host", "0.0.0.0", "--port", "8001"]
