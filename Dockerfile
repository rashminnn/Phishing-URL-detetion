FROM node:18 as build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app

# Copy only what's needed from the build stage
COPY --from=build /app/build ./build
COPY requirements.txt .
COPY app.py .
COPY phishing_model_xgboost.pkl .

# Install Python dependencies with clear error output
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV PRODUCTION=True
ENV PORT=8080
ENV SECRET_KEY=ba04e2f1-06c4-41f5-9bc1-be2b665c7d23

# Create a non-root user and switch to it
RUN useradd -m appuser
USER appuser

# Use shell form of CMD to enable variable substitution
CMD gunicorn app:app --bind 0.0.0.0:8080