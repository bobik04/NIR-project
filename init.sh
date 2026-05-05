#!/bin/bash

# SmartScan Initialization Script (Fixed dependency conflicts and 404 errors)
echo "[*] Обновление системы..."
sudo apt-get update && sudo apt-get install -y git wget curl build-essential libssl-dev python3-dev python3-pip python3-venv apt-transport-https ca-certificates software-properties-common

# Установка Docker (необходим для поднятия проекта в контейнере)
if ! command -v docker &> /dev/null; then
    echo "[*] Установка Docker..."
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose
    sudo usermod -aG docker $USER
fi

# Создание структуры проекта (можно адаптировать под свои нужды)
echo "[*] Настройка структуры проекта..."
PROJECT_DIR="$HOME/smart-contract-analyzer"
ENV_DIR="$HOME/analyzer-env"
mkdir -p $PROJECT_DIR/contracts/{eth,fabric}
mkdir -p $PROJECT_DIR/reports

# Установка Go
if ! command -v go &> /dev/null; then
    echo "[*] Установка Go..."
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

# Делаем симлинки в системную директорию, чтобы Python всегда видел команды go и gofmt
sudo ln -sf /usr/local/go/bin/go /usr/bin/go
sudo ln -sf /usr/local/go/bin/gofmt /usr/bin/gofmt
export PATH=$PATH:/usr/local/go/bin

# Предварительное кэширование библиотек Fabric и CCKit
echo "[*] Кэширование библиотек Hyperledger Fabric и CCKit..."
mkdir -p /tmp/fabric-cache && cd /tmp/fabric-cache
go mod init dummycache
go get github.com/hyperledger/fabric-contract-api-go/contractapi@latest
go get github.com/s7techlab/cckit/testing/expect@latest
go get github.com/hyperledger/fabric-chaincode-go/shimtest@latest
go mod tidy
cd - && rm -rf /tmp/fabric-cache

# Настройка Python venv
echo "[*] Настройка Python окружения..."
python3 -m venv $ENV_DIR
source $ENV_DIR/bin/activate

pip install --upgrade pip wheel "setuptools<66.0.0"

echo "[*] Установка анализаторов (Slither, Mythril, Solc)..."
pip install z3-solver==4.12.1.0
pip install mythril slither-analyzer solc-select

# Установка Solidity
echo "[*] Установка Solidity 0.8.28..."
rm -f $ENV_DIR/bin/solc
curl -L https://github.com/ethereum/solidity/releases/download/v0.8.28/solc-static-linux -o $ENV_DIR/bin/solc
chmod +x $ENV_DIR/bin/solc

# Установка Gosec
echo "[*] Установка Gosec..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Установка Echidna (релиз 2.3.2 с архитектурным именем архива)
if ! command -v echidna &> /dev/null; then
    echo "[*] Установка Echidna..."
    wget https://github.com/crytic/echidna/releases/download/v2.3.2/echidna-2.3.2-x86_64-linux.tar.gz
    tar -xf echidna-2.3.2-x86_64-linux.tar.gz
    sudo mv echidna /usr/local/bin/
    rm echidna-2.3.2-x86_64-linux.tar.gz
fi

echo "[+] Установка завершена успешно!"