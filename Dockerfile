FROM python:3.12-slim

# No build toolchain is needed: the pikepdf wheel ships libqpdf precompiled.
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Runs as a non-root user with no home and no shell. If a malformed PDF ever achieves
# execution inside qpdf, it lands here: no privileges, no credentials, no egress.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin sanitizer
USER sanitizer

ENV PORT=8080
EXPOSE 8080

# One worker, low concurrency: the work is CPU-bound, so queueing is the correct response
# to load rather than thrashing. --timeout kills a worker stuck on a pathological document,
# which is the failure mode a size cap cannot prevent.
CMD exec gunicorn \
      --bind :$PORT \
      --workers 1 \
      --threads 4 \
      --timeout 30 \
      --graceful-timeout 5 \
      --access-logfile - \
      --error-logfile - \
      app:app
