# ===================== STAGE 1: Build React Frontend =====================
FROM node:18 AS frontend-build

WORKDIR /app

# Copy and install dependencies
COPY package*.json ./
RUN npm install

# Copy frontend code and build it
COPY . ./
RUN npm run build


# ===================== STAGE 2: Flask Backend =====================
FROM python:3.11-slim

WORKDIR /app

# Copy built frontend from previous stage
COPY --from=frontend-build /app/build ./build

# Copy backend code and model
COPY requirements.txt .
COPY app.py .
COPY phishing_model_xgboost.pkl .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV SECRET_KEY="your-secret-key"
ENV MODEL_PATH=./phishing_model_xgboost.pkl
# PORT will be passed by Railway, default fallback is optional
ENV PORT=5000

# Create non-root user (security best practice)
RUN useradd -m appuser && chown -R appuser /app
USER appuser

# Expose the port (optional, for documentation)
EXPOSE 5000

# Run Flask app using Gunicorn
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:$PORT", "--workers", "1", "--threads", "8", "--timeout", "120"]
