FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy model and application code
COPY phishing_model_xgboost.pkl .
COPY app.py .

# Set environment variables
ENV MODEL_PATH="./phishing_model_xgboost.pkl"
ENV FLASK_ENV="production"
ENV PORT=8080

# Expose the port
EXPOSE 8080

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]