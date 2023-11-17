pragma solidity ^0.5.16;

contract Login {
    event LoginAttempt(address sender, string challenge);
    
    function login(string memory challenge) public {
        emit LoginAttempt(msg.sender, challenge);
    }
}
