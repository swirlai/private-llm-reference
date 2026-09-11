FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Dependencies first so edits to the service code do not invalidate the layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root: nothing in this service needs to write to the image.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8093
CMD ["python", "server.py"]
