// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**

@title Reentrancy

@dev Целевой уязвимый контракт.
*/
contract Reentrancy {
mapping(address => uint256) public balances;

function deposit() public payable {
balances[msg.sender] += msg.value;
}

function withdraw() public {
uint256 bal = balances[msg.sender];
require(bal > 0);

 (bool sent, ) = msg.sender.call{value: bal}("");
 require(sent, "Failed to send Ether");

 balances[msg.sender] = 0;


}
}

/**

@title EchidnaTest

@dev Тестовый контракт, который Echidna будет использовать как точку входа.

Он наследует уязвимый контракт и сам же имитирует атаку.
*/
contract EchidnaTest is Reentrancy {
bool private isAttacking;
uint256 private phantomBalance;

constructor() payable {}

// Эмуляция депозита через прокси, чтобы отслеживать "ожидаемый" баланс
function test_deposit() public payable {
if (msg.value > 0 && msg.value < 10 ether) {
deposit();
phantomBalance += msg.value;
}
}

// Эмуляция вывода с флагом атаки
function test_withdraw() public {
if (balances[address(this)] > 0) {
isAttacking = true;
withdraw();
isAttacking = false;
}
}

// Рекурсивный вызов (Reentrancy)
receive() external payable {
if (isAttacking && address(msg.sender).balance >= msg.value) {
// Пытаемся вызвать вывод еще раз, пока баланс жертвы не иссякнет
withdraw();
}
}

/**

@dev ИНВАРИАНТ: Сумма, которую мы внесли (phantomBalance),

никогда не должна превышать реальный баланс контракта, если вывод работает честно.

При Reentrancy атаке баланс контракта упадет до 0, а phantomBalance останется положительным.
*/
function echidna_check_reentrancy() public view returns (bool) {
// Если мы все вывели честно, оба должны быть 0.
// Если была атака, баланс контракта будет меньше, чем мы "ожидаем" по логике честных транзакций.
return address(this).balance >= balances[address(this)];
}
}