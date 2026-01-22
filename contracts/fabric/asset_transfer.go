package main

import (
    "encoding/json"
    "fmt"
    "github.com/hyperledger/fabric-chaincode-go/shim"
    pb "github.com/hyperledger/fabric-protos-go/peer"
)

// SmartContract структура chaincode
type SmartContract struct {
}

// Asset описывает актив в блокчейне
type Asset struct {
    ID             string `json:"ID"`
    Color          string `json:"color"`
    Size           int    `json:"size"`
    Owner          string `json:"owner"`
    AppraisedValue int    `json:"appraisedValue"`
}

// Init инициализирует chaincode
func (s *SmartContract) Init(stub shim.ChaincodeStubInterface) pb.Response {
    return shim.Success(nil)
}

// Invoke основная точка входа для транзакций
func (s *SmartContract) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
    function, args := stub.GetFunctionAndParameters()
    
    switch function {
    case "InitLedger":
        return s.InitLedger(stub)
    case "CreateAsset":
        return s.CreateAsset(stub, args)
    case "ReadAsset":
        return s.ReadAsset(stub, args)
    case "UpdateAsset":
        return s.UpdateAsset(stub, args)
    case "DeleteAsset":
        return s.DeleteAsset(stub, args)
    case "GetAllAssets":
        return s.GetAllAssets(stub)
    default:
        return shim.Error(fmt.Sprintf("Неизвестная функция: %s", function))
    }
}

// InitLedger инициализирует ledger начальными данными
func (s *SmartContract) InitLedger(stub shim.ChaincodeStubInterface) pb.Response {
    assets := []Asset{
        {ID: "asset1", Color: "blue", Size: 5, Owner: "Tomoko", AppraisedValue: 300},
        {ID: "asset2", Color: "red", Size: 5, Owner: "Brad", AppraisedValue: 400},
        {ID: "asset3", Color: "green", Size: 10, Owner: "Jin Soo", AppraisedValue: 500},
        {ID: "asset4", Color: "yellow", Size: 10, Owner: "Max", AppraisedValue: 600},
        {ID: "asset5", Color: "black", Size: 15, Owner: "Adriana", AppraisedValue: 700},
        {ID: "asset6", Color: "white", Size: 15, Owner: "Michel", AppraisedValue: 800},
    }
    
    for _, asset := range assets {
        assetJSON, err := json.Marshal(asset)
        if err != nil {
            return shim.Error(err.Error())
        }
        
        err = stub.PutState(asset.ID, assetJSON)
        if err != nil {
            return shim.Error(fmt.Sprintf("Ошибка записи актива %s: %s", asset.ID, err.Error()))
        }
    }
    
    return shim.Success(nil)
}

// CreateAsset создает новый актив в блокчейне
func (s *SmartContract) CreateAsset(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    if len(args) != 5 {
        return shim.Error("Требуется 5 аргументов: ID, color, size, owner, appraisedValue")
    }
    
    // Валидация входных данных
    if args[0] == "" {
        return shim.Error("ID актива не может быть пустым")
    }
    
    // Проверка существования актива
    existing, err := stub.GetState(args[0])
    if err != nil {
        return shim.Error(fmt.Sprintf("Ошибка проверки актива: %s", err.Error()))
    }
    if existing != nil {
        return shim.Error(fmt.Sprintf("Актив %s уже существует", args[0]))
    }
    
    // Создание актива
    size := 0
    fmt.Sscanf(args[2], "%d", &size)
    
    value := 0
    fmt.Sscanf(args[4], "%d", &value)
    
    asset := Asset{
        ID:             args[0],
        Color:          args[1],
        Size:           size,
        Owner:          args[3],
        AppraisedValue: value,
    }
    
    assetJSON, err := json.Marshal(asset)
    if err != nil {
        return shim.Error(err.Error())
    }
    
    err = stub.PutState(asset.ID, assetJSON)
    if err != nil {
        return shim.Error(err.Error())
    }
    
    return shim.Success(assetJSON)
}

// ReadAsset возвращает актив по ID
func (s *SmartContract) ReadAsset(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    if len(args) != 1 {
        return shim.Error("Требуется 1 аргумент: ID актива")
    }
    
    assetJSON, err := stub.GetState(args[0])
    if err != nil {
        return shim.Error(fmt.Sprintf("Ошибка чтения актива: %s", err.Error()))
    }
    if assetJSON == nil {
        return shim.Error(fmt.Sprintf("Актив %s не найден", args[0]))
    }
    
    return shim.Success(assetJSON)
}

// UpdateAsset обновляет существующий актив
func (s *SmartContract) UpdateAsset(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    if len(args) != 5 {
        return shim.Error("Требуется 5 аргументов: ID, color, size, owner, appraisedValue")
    }
    
    // Проверка существования
    existing, err := stub.GetState(args[0])
    if err != nil {
        return shim.Error(fmt.Sprintf("Ошибка проверки актива: %s", err.Error()))
    }
    if existing == nil {
        return shim.Error(fmt.Sprintf("Актив %s не найден", args[0]))
    }
    
    // Обновление актива
    size := 0
    fmt.Sscanf(args[2], "%d", &size)
    
    value := 0
    fmt.Sscanf(args[4], "%d", &value)
    
    asset := Asset{
        ID:             args[0],
        Color:          args[1],
        Size:           size,
        Owner:          args[3],
        AppraisedValue: value,
    }
    
    assetJSON, err := json.Marshal(asset)
    if err != nil {
        return shim.Error(err.Error())
    }
    
    err = stub.PutState(asset.ID, assetJSON)
    if err != nil {
        return shim.Error(err.Error())
    }
    
    return shim.Success(assetJSON)
}

// DeleteAsset удаляет актив из блокчейна
func (s *SmartContract) DeleteAsset(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    if len(args) != 1 {
        return shim.Error("Требуется 1 аргумент: ID актива")
    }
    
    // Проверка существования
    existing, err := stub.GetState(args[0])
    if err != nil {
        return shim.Error(fmt.Sprintf("Ошибка проверки актива: %s", err.Error()))
    }
    if existing == nil {
        return shim.Error(fmt.Sprintf("Актив %s не найден", args[0]))
    }
    
    err = stub.DelState(args[0])
    if err != nil {
        return shim.Error(err.Error())
    }
    
    return shim.Success(nil)
}

// GetAllAssets возвращает все активы из блокчейна
func (s *SmartContract) GetAllAssets(stub shim.ChaincodeStubInterface) pb.Response {
    resultsIterator, err := stub.GetStateByRange("", "")
    if err != nil {
        return shim.Error(err.Error())
    }
    defer resultsIterator.Close()
    
    var assets []Asset
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return shim.Error(err.Error())
        }
        
        var asset Asset
        err = json.Unmarshal(queryResponse.Value, &asset)
        if err != nil {
            return shim.Error(err.Error())
        }
        assets = append(assets, asset)
    }
    
    assetsJSON, err := json.Marshal(assets)
    if err != nil {
        return shim.Error(err.Error())
    }
    
    return shim.Success(assetsJSON)
}

// main функция запуска chaincode
func main() {
    err := shim.Start(new(SmartContract))
    if err != nil {
        fmt.Printf("Ошибка запуска chaincode: %s", err)
    }
}