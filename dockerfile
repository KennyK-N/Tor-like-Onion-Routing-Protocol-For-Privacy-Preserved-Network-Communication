FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    tmux tcpdump sudo \
    build-essential curl vim \
    net-tools lsof \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN python3 -m venv .venv

RUN .venv/bin/pip install --upgrade pip && \
    .venv/bin/pip install -r requirements.txt

#RUN mkdir -p /app/logs /app/capture

#CMD ["bash", "run.sh"]