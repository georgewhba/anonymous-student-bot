FROM python:3.12-slim

# Install system dependencies (tesseract, libmagic, ffmpeg, curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-ara \
    tesseract-ocr-eng \
    ffmpeg \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create media temp directory
RUN mkdir -p media_tmp

# Auto-apply database migrations on startup and launch bot
CMD ["sh", "-c", "alembic upgrade head && python main.py"]
