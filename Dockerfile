FROM node:18 as build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . ./
RUN npm run build

FROM python:3.11.8-slim
WORKDIR /app
COPY --from=build /app/build ./build
COPY requirements.txt .
COPY app.py .
COPY phishing_model_xgboost.pkl .
RUN pip install --no-cache-dir -r requirements.txt
ENV PRODUCTION=True
ENV PORT=8080

CMD gunicorn app:app --bind 0.0.0.0:$PORT