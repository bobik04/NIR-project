package main

import (
"fmt"
"math/rand"
"time"
"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract определяет структуру чейнкода
type SmartContract struct {
	contractapi.Contract
	}

	// Asset описывает объект в реестре
	type Asset struct {
		ID    string json:"id"
		Value int    json:"value"
	}

	// CreateAsset содержит уязвимость недетерминизма
	func (s *SmartContract) CreateAsset(ctx contractapi.TransactionContextInterface, id string) error {
	// УЯЗВИМОСТЬ: Использование math/rand (Недетерминированное поведение)
	// Использование random приведет к тому, что транзакция не будет подтверждена (Endorsement Policy Failure).
	rand.Seed(time.Now().UnixNano())
	randomValue := rand.Intn(100)

	asset := Asset{
		ID:    id,
		Value: randomValue,
	}

	assetJSON, err := ctx.GetStub().PutState(id, []byte(fmt.Sprintf("%v", asset)))
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}

	return nil


	}

	// UpdateAsset уязвим для отсутствия проверки доступа
	func (s *SmartContract) UpdateAsset(ctx contractapi.TransactionContextInterface, id string, newValue int) error {
	// УЯЗВИМОСТЬ: Отсутствие проверки вызывающей стороны (Access Control)
	// Любой пользователь может изменить значение любого актива.
	asset := Asset{
		ID:    id,
		Value: newValue,
	}
	return ctx.GetStub().PutState(id, []byte(fmt.Sprintf("%v", asset)))
	}

	func main() {
	assetChaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating asset-transfer-basic chaincode: %v", err)
	}

	if err := assetChaincode.Start(); err != nil {
		log.Panicf("Error starting asset-transfer-basic chaincode: %v", err)
	}

}