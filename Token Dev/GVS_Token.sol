// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.7;

contract GVSToken {
  address public owner = msg.sender;
  uint256 public totalSupply = 1000 ; //total number of available token
  mapping (address => uint256) private _balances;
  mapping (address => mapping(address => uint256)) private _allowed;
  //events will be fired for transfer and approval of tokens
  event Transfer (address indexed _from, address indexed _to, uint256 _value);
  event Approval (address indexed _owner, address indexed _spender, uint256 _value);

  constructor () {
    _balances[msg.sender] = 1000;
  }

  function _transfer (address _from, address _to, uint256 _value) internal {
    require(_from != address(0), "ERC20: transfer from the zero address");

    require(_to != address(0), "ERC20: transfer to the zero address");
    require(_value <= _balances[_from], "ERC20: transfer amount exceeds balance");

    _balances[_from] = _balances[_from] - _value;
    _balances[_to] = _balances[_to] + _value;
    emit Transfer(_from, _to, _value);
  }

  function _burn (address _from, uint256 _value) internal {
    require(_from != address(0), "ERC20: burn from the zero address");
    require(_value <= _balances[_from], "ERC20: burn amount exceeds balance");

    _balances[_from] = _balances[_from] - _value;
    totalSupply = totalSupply - _value;
    emit Transfer(_from, address(0), _value);
  }

  function _mint (address _to, uint256 _value) internal {
    require(_to != address(0), "ERC20: mint to the zero address");
    totalSupply = totalSupply + _value;

    _balances[_to] = _balances[_to] + _value;
    emit Transfer(address(0), _to, _value);
  }

  function name () public pure returns (string memory) {
    return "GVSToken";
  }

  function symbol () public pure returns (string memory) {
    return "GVS";
  }

  function balanceOf (address _owner) public view returns (uint256) {
    return _balances[_owner];
  }

  function transfer (address _to, uint256 _value) public returns (bool) {
    _transfer(msg.sender, _to, _value);
    return true;
  }

  function transferFrom (address _from, address _to, uint _value) public returns (bool) {

    require(_value <= _allowed[_from][msg.sender], "Not allowed");
    _transfer(_from, _to, _value);
    _allowed[_from][msg.sender] = _allowed[_from][msg.sender] -

    _value;

    return true;
  }

  function approve (address _spender, uint256 _value) public returns (bool) {
    _allowed[msg.sender][_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance (address _owner, address _spender) public view returns (uint256) {
    return _allowed[_owner][_spender];
  }

  function burn (uint256 _value) public returns (bool) {
    _burn(msg.sender, _value);
    return true;
  }

  function burnFrom (address _from, uint256 _value) public returns (bool) {
    require(_value <= _allowed[_from][msg.sender], "Not allowed");
    _burn(_from, _value);
    return true;
  }

  function mint (address _to, uint256 _value) public returns (bool) {
    require(msg.sender == owner, "Only owner can mint coins");
    _mint(_to, _value);
    return true;
  }

  function buy(uint256 _value) payable public {
    _transfer(owner, msg.sender, _value);
  }

  function sell(uint256 _value) public returns (bool) {
    require(_value <= _balances[msg.sender], "Insufficient balance");
    require(address(this).balance >= _value / 1010, "Sorry, we don't have enough GVS Tokens for selling");

    _transfer(msg.sender, owner, _value);
    payable(msg.sender).transfer(_value / 1010);
    return true;
  }

  function withdraw(uint256 _value) public {
    require(msg.sender == owner, "Only owner can withdraw");
    payable(owner).transfer(_value);
  }

}

