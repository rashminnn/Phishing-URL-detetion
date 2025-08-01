FROM node:18 as build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . ./
RUN npm run build --verbose
RUN ls -la /app/build

FROM python:3.11-slim
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y libgomp1 && rm -rf /var/lib/apt/lists/*

# Copy files
COPY --from=build /app/build ./build
COPY requirements.txt .
COPY app.py .
COPY phishing_model_xgboost.pkl .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Environment variables
ENV PRODUCTION=True
ENV SECRET_KEY=b5da9cc96d22fbc606d7ff6c16e9a309d14108e45627ea79a7092dc9c8e3a6ec
ENV MODEL_PATH=./phishing_model_xgboost.pkl

# Create non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Updated CMD with better timeout and worker configuration
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:$PORT", "--workers", "1", "--threads", "4", "--timeout", "45", "--keep-alive", "2", "--max-requests", "1000", "--max-requests-jitter", "100", "--preload"]