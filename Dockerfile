FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN python -m loglens generate && python -m loglens analyze data/sample.log
EXPOSE 8000
CMD ["python", "-m", "loglens", "serve", "--host", "0.0.0.0", "--port", "8000"]
