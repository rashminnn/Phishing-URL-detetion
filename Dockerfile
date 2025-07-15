FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8080
ENV MODEL_PATH=./phishing_model_xgboost.pkl
ENV FLASK_ENV=production

CMD gunicorn --bind 0.0.0.0:$PORT app:app