// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**

@title SecureVault

@dev Исправленный безопасный контракт.

Инвариант: баланс контракта всегда должен быть больше или равен сумме всех учтенных депозитов.
*/
contract SecureVault {
    mapping(address => uint256) public balances;
    uint256 public totalVaultBalance;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    /**

    @dev Функция депозита.
    */
    function deposit() public payable {
        require(msg.value > 0, "Amount must be greater than 0");

        balances[msg.sender] += msg.value;
        totalVaultBalance += msg.value;

        emit Deposited(msg.sender, msg.value);
    }

    /**

    @dev Безопасная функция вывода средств.
    */
    function withdraw(uint256 amount) public {
        // Checks
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(address(this).balance >= amount, "Contract balance insufficient");

        // Effects
        balances[msg.sender] -= amount;
        totalVaultBalance -= amount;

        emit Withdrawn(msg.sender, amount);

        // Interactions
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    /**

    @dev Функция-инвариант для Echidna.

    Теперь она встроена в контракт, и Echidna будет проверять её при каждом вызове.
    */
    function echidna_check_solvency() public view returns (bool) {
        return address(this).balance >= totalVaultBalance;
    }

    /**

    @dev Вспомогательная функция для проверки баланса.
    */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}