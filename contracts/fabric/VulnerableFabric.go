package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract определяет структуру контракта
type SmartContract struct {
	contractapi.Contract
}

// Asset структура данных
type Asset struct {
	ID    string `json:"id"`
	Value int    `json:"value"`
}

// CreateRiskyAsset создает актив с использованием случайных чисел (НЕДЕТЕРМИНИЗМ)
// Это вызовет срабатывание Gosec (G404) и провал динамического теста симулятора
func (s *SmartContract) CreateRiskyAsset(ctx contractapi.TransactionContextInterface, id string) error {
	// ОШИБКА: Использование генератора случайных чисел в блокчейне запрещено
	// Разные узлы получат разные значения, консенсус упадет
	rand.Seed(time.Now().UnixNano())
	randomValue := rand.Intn(1000)

	asset := Asset{
		ID:    id,
		Value: randomValue,
	}

	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, assetJSON)
}

// UnhandledError демонстрирует игнорирование ошибок (G104)
func (s *SmartContract) UnhandledError(ctx contractapi.TransactionContextInterface, id string) error {
	// ОШИБКА: Результат PutState не проверяется
	ctx.GetStub().PutState(id, []byte("data"))
	return nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		fmt.Printf("Error creating chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting chaincode: %s", err.Error())
	}
}