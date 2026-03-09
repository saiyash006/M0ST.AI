FROM python:3.11-slim

# Install system dependencies for radare2 and GDB
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Install radare2 from git (latest stable)
RUN git clone --depth=1 https://github.com/radareorg/radare2.git /tmp/radare2 \
    && cd /tmp/radare2 \
    && sys/install.sh \
    && rm -rf /tmp/radare2

WORKDIR /app

# Install Python dependencies first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source
COPY . .

# Default: launch interactive CLI
CMD ["python", "main.py"]
