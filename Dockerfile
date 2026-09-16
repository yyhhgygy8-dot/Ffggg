FROM python:3.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEBIAN_FRONTEND=noninteractive
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /data
ENV PORT=5000 DATA_DIR=/data ADMIN_USERNAME=admin ADMIN_PASSWORD=admin123
EXPOSE 5000
CMD ["gunicorn","--bind","0.0.0.0:5000","--workers","1","--threads","8","--timeout","180","wsgi:app"]
