# Dockerfile for Render Cloud Deployment
# ChatPhishDetector (IEEE Access 2024 Base Paper Implementation)

FROM python:3.10-slim

# Prevent prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install official Debian Chromium browser and required system libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    fonts-liberation \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set Chrome path for crawler.py
ENV CHROME_PATH="/usr/bin/chromium"
ENV CRAWLER_HEADLESS="true"

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose Render web port
EXPOSE 8501

# Start Streamlit application
CMD ["sh", "-c", "streamlit run app.py --server.port=${PORT:-8501} --server.address=0.0.0.0"]
