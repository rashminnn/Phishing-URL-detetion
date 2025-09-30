FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y libgomp1 && rm -rf /var/lib/apt/lists/*

# Copy backend files only
COPY requirements.txt .
COPY app.py .
COPY phishing_model_xgboost.pkl .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Environment variables
ENV PRODUCTION=True
ENV MODEL_PATH=./phishing_model_xgboost.pkl

# Hugging Face Spaces uses port 7860
EXPOSE 7860

# Run the Flask app on port 7860
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:7860", "--workers", "1", "--threads", "4", "--timeout", "120", "--keep-alive", "5"]