# --------- Stage 1: Build frontend (Node.js) ---------
FROM node:18 as build
WORKDIR /app

# Install dependencies and build frontend
COPY package*.json ./
RUN npm install
COPY . ./
RUN npm run build --verbose

# Optional: See what was built
RUN ls -la /app/build

# --------- Stage 2: Backend (Python) ---------
FROM python:3.11-slim
WORKDIR /app

# Install system packages and clean up cache
RUN apt-get update && apt-get install -y libgomp1 && rm -rf /var/lib/apt/lists/*

# Copy frontend build and backend code
COPY --from=build /app/build ./build
COPY requirements.txt .
COPY app.py .
COPY phishing_model_xgboost.pkl .
COPY start.sh .

# ✅ Set executable permission on start.sh before switching users
RUN chmod +x start.sh

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV PRODUCTION=True
ENV SECRET_KEY=b5da9cc96d22fbc606d7ff6c16e9a309d14108e45627ea79a7092dc9c8e3a6ec
ENV MODEL_PATH=./phishing_model_xgboost.pkl
ENV PORT=8080

# Create and switch to non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Run the app using the startup script
CMD ["./start.sh"]
