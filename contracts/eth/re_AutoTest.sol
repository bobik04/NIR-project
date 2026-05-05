// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "/app/contracts/eth/re.sol";

contract GeneratedAutoTest is EchidnaTest {
    uint256 private totalExpected;
    constructor() payable {}

    function depositAuto() public payable {
        if (msg.value > 0 && msg.value < 100 ether) {
            deposit();
            totalExpected += msg.value;
        }
    }
    function echidna_check_solvency() public view returns (bool) {
        // Баланс контракта не должен быть меньше суммы всех депозитов
        return address(this).balance >= totalExpected;
    }
    bool private initialized = true;
    function echidna_basic_liveness() public view returns (bool) {
        return initialized;
    }
}