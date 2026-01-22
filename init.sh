#!/bin/bash

# SmartScan Initialization Script
# Устанавливает: Python env, Go, Slither, Mythril, Echidna, Gosec, Solc

echo "[*] Обновление системы..."
sudo apt-get update && sudo apt-get install -y git wget curl build-essential libssl-dev python3-dev python3-pip python3-venv

echo "[*] Настройка структуры проекта..."
PROJECT_DIR="$HOME/smart-contract-analyzer"
ENV_DIR="$HOME/analyzer-env"
mkdir -p $PROJECT_DIR/contracts/{eth,fabric}
mkdir -p $PROJECT_DIR/reports

# Установка Go (если нет)
if ! command -v go &> /dev/null; then
    echo "[*] Установка Go..."
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

# Настройка Python venv
echo "[*] Настройка Python окружения..."
python3 -m venv $ENV_DIR
source $ENV_DIR/bin/activate

pip install --upgrade pip
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    pip install slither-analyzer solc-select mythril
fi

# Установка Solidity (бинарник)
echo "[*] Установка Solidity 0.8.28..."
rm -f $ENV_DIR/bin/solc
curl -L https://github.com/ethereum/solidity/releases/download/v0.8.28/solc-static-linux -o $ENV_DIR/bin/solc
chmod +x $ENV_DIR/bin/solc

# Установка Gosec
echo "[*] Установка Gosec..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Установка Echidna
echo "[*] Установка Echidna..."
wget https://github.com/crytic/echidna/releases/download/v2.2.3/echidna-2.2.3-Linux.tar.gz
tar -xf echidna-2.2.3-Linux.tar.gz
mv echidna $ENV_DIR/bin/
rm echidna-2.2.3-Linux.tar.gz

echo "export SOLC=$ENV_DIR/bin/solc" >> ~/.bashrc
echo "source $ENV_DIR/bin/activate" >> ~/.bashrc
echo "export PATH=\$PATH:$HOME/go/bin" >> ~/.bashrc

echo "[+] Установка завершена! Перезапустите терминал или введите: source ~/.bashrc"