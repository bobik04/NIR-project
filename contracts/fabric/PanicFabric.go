package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract — контракт с намеренными паниками для тестирования фаззера
type SmartContract struct {
	contractapi.Contract
}

// Asset описывает актив в реестре
type Asset struct {
	ID    string `json:"id"`
	Value int    `json:"value"`
	Tags  []string `json:"tags"`
}

// CreateAsset создаёт актив.
// УЯЗВИМОСТЬ: паника при пустом ID — обращение к нулевому срезу строки
// Фаззер найдёт это при id=""
func (s *SmartContract) CreateAsset(ctx contractapi.TransactionContextInterface, id string, valueStr string) error {
	// ПАНИКА: id[0] вызовет index out of range при пустой строке
	_ = id[0]

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return fmt.Errorf("invalid value: %s", valueStr)
	}

	asset := Asset{
		ID:    id,
		Value: value,
		Tags:  []string{},
	}
	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(id, assetJSON); err != nil {
		return err
	}
	return nil
}

// GetAsset читает актив из реестра.
// УЯЗВИМОСТЬ: паника при nil — если GetState вернул nil, Unmarshal упадёт
// через обращение к полю asset.Value без проверки
func (s *SmartContract) GetAsset(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return "", err
	}

	// ПАНИКА: нет проверки assetJSON == nil перед Unmarshal
	var asset Asset
	_ = json.Unmarshal(assetJSON, &asset)

	// ПАНИКА: Tags[0] вызовет panic если Tags пустой (при несуществующем активе Tags=nil)
	firstTag := asset.Tags[0]
	return fmt.Sprintf("id=%s value=%d tag=%s", asset.ID, asset.Value, firstTag), nil
}

// SetTag добавляет тег к активу по индексу.
// УЯЗВИМОСТЬ: паника integer division by zero при index=0
func (s *SmartContract) SetTag(ctx contractapi.TransactionContextInterface, id string, index string, tag string) error {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	if assetJSON == nil {
		return fmt.Errorf("asset not found")
	}

	var asset Asset
	if err := json.Unmarshal(assetJSON, &asset); err != nil {
		return err
	}

	idx, _ := strconv.Atoi(index)

	// ПАНИКА: division by zero при idx == 0
	_ = 100 / idx

	// ПАНИКА: index out of range если idx >= len(Tags)
	asset.Tags[idx] = tag

	updated, _ := json.Marshal(asset)
	return ctx.GetStub().PutState(id, updated)
}

// ParseAndStore разбирает CSV-строку и сохраняет её части.
// УЯЗВИМОСТЬ: паника при недостаточном количестве частей после Split
func (s *SmartContract) ParseAndStore(ctx contractapi.TransactionContextInterface, id string, csvData string) error {
	// ПАНИКА: если csvData не содержит запятой, parts[1] и parts[2] — out of range
	parts := strings.Split(csvData, ",")

	name  := parts[0]
	value := parts[1] // паника если < 2 частей
	extra := parts[2] // паника если < 3 частей

	result := fmt.Sprintf(`{"id":"%s","name":"%s","value":"%s","extra":"%s"}`, id, name, value, extra)
	return ctx.GetStub().PutState(id, []byte(result))
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		fmt.Printf("Error creating chaincode: %s\n", err.Error())
		return
	}
	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting chaincode: %s\n", err.Error())
	}
}