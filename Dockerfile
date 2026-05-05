FROM python:3.10-slim

# --- Системные зависимости ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    pkg-config \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- Go ---
ENV GO_VERSION=1.21.5
RUN curl -sOL https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/root/go
ENV GOMODCACHE=/root/go/pkg/mod
ENV PATH=$PATH:/root/go/bin

# --- Gosec ---
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.20.0

# --- Предварительное кэширование Fabric-зависимостей (ускоряет sandbox) ---
RUN mkdir -p /tmp/fabric-cache && cd /tmp/fabric-cache && \
    go mod init dummycache && \
    go get github.com/hyperledger/fabric-contract-api-go/contractapi@latest && \
    go get github.com/hyperledger/fabric-chaincode-go/shimtest@latest && \
    go mod tidy && \
    cd / && rm -rf /tmp/fabric-cache

# --- Python-зависимости ---
COPY requirements.txt /tmp/requirements.txt

RUN pip install --upgrade pip wheel "setuptools<66.0.0"
# z3-solver 
RUN pip3 install --no-cache-dir --only-binary :all: z3-solver==4.12.1.0 || \
    pip3 install --no-cache-dir --only-binary :all: z3-solver==4.13.0.0

# mythril + slither + solc-select (актуальные стабильные версии, совместимые с z3-solver
RUN pip install --no-cache-dir mythril slither-analyzer solc-select
# --- Solidity (версия совпадает с security.yml) ---
RUN solc-select install 0.8.28 && solc-select use 0.8.28

# --- Echidna 2.3.2 (актуальная стабильная версия) ---
RUN wget -q https://github.com/crytic/echidna/releases/download/v2.3.2/echidna-2.3.2-x86_64-linux.tar.gz \
    -O /tmp/echidna.tar.gz && \
    tar -xzf /tmp/echidna.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/echidna && \
    rm /tmp/echidna.tar.gz

WORKDIR /app

COPY . .

RUN mkdir -p reports contracts/eth contracts/fabric

ENTRYPOINT ["python3", "smartScan.py"]
CMD ["--help"]