FROM python:3.13-slim

RUN apt-get update && apt-get install -y \
    cmake ninja-build gcc python3-dev git libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    python -c "import oqs"

COPY src/ ./src/
COPY scripts/ ./scripts/

CMD ["python", "scripts/run_node.py"]
