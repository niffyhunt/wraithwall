FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY packages/canary-kit packages/canary-kit
COPY packages/dml-spec packages/dml-spec
COPY packages/honeypot-mitre packages/honeypot-mitre
COPY packages/ravenscan packages/ravenscan
RUN pip install --no-cache-dir packages/canary-kit packages/dml-spec packages/honeypot-mitre packages/ravenscan
COPY pyproject.toml README.md requirements.txt ./
COPY src ./src
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["gunicorn", "wraithwall:create_app()", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120"]