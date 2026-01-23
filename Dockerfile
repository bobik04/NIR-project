FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    libssl-dev \
    pkg-config \
    unzip \
    && rm -rf /var/lib/apt/lists/*

ENV GO_VERSION 1.21.5
RUN curl -OL https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin

RUN pip3 install solc-select && \
    solc-select install 0.8.23 && \
    solc-select use 0.8.23

RUN pip3 install slither-analyzer mythril
RUN curl -L https://github.com/crytic/echidna/releases/download/v2.2.1/echidna-2.2.1-Ubuntu-22.04.tar.gz | tar xz -C /usr/local/bin

RUN curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b /usr/local/bin v2.18.2

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p reports contracts

ENTRYPOINT ["python3", "smartScan.py"]
CMD ["--help"]