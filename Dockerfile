FROM node:18 as build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app

# Copy files
COPY --from=build /app/build ./build
COPY requirements.txt .
COPY app.py .
COPY phishing_model_xgboost.pkl .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV PRODUCTION=True
ENV SECRET_KEY=b5da9cc96d22fbc606d7ff6c16e9a309d14108e45627ea79a7092dc9c8e3a6ec
ENV MODEL_PATH=./phishing_model_xgboost.pkl
# Hardcode port in environment
ENV PORT=8080

# Create a non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Hardcoded port with no variable expansion
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--timeout", "120"]