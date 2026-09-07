FROM python:3.12-slim AS builder
WORKDIR /app
COPY app.py /app/app.py

FROM python:3.12-slim
RUN groupadd -g 1000 appuser && useradd -u 1000 -g appuser -m appuser
WORKDIR /app
COPY --from=builder /app/app.py /app/app.py
USER 1000:1000
EXPOSE 8080
CMD ["python3","app.py"]