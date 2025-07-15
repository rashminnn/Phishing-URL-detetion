# ========== STAGE 1: Build React Frontend ==========
FROM node:18 as build
WORKDIR /app

# Install frontend dependencies and build React app
COPY package*.json ./
RUN npm install
COPY . ./
RUN npm run build

# ========== STAGE 2: Setup Flask Backend ==========
FROM python:3.11-slim
WORKDIR /app

# Copy frontend build output
COPY --from=build /app/build ./build

# Copy backend files
COPY requirements.txt .             # Your requirements.txt for Python packages
COPY app.py .                       # Your Flask backend
COPY phishing_model_xgboost.pkl .   # Your ML model

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables (safe for Railway)
ENV PRODUCTION=True
ENV SECRET_KEY=b5da9cc96d22fbc606d7ff6c16e9a309d14108e45627ea79a7092dc9c8e3a6ec
ENV MODEL_PATH=./phishing_model_xgboost.pkl
ENV PORT=5000  # Default fallback, Railway will override

# Create a non-root user (security best practice)
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# ========= START APP =========
# Use shell form so that ${PORT} is expanded properly
CMD ["/bin/sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT} --workers 1 --threads 8 --timeout 120"]
