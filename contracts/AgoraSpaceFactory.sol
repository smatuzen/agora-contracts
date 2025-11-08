// SPDX-License-Identifier: MIT
pragma solidity 0.8.7;

import "./AgoraSpace.sol";
import "./token/AgoraToken.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

/// @title AgoraSpaceFactory
/// @notice Deploys Agora Space contracts and their associated AgoraTokens for communities
contract AgoraSpaceFactory is Ownable {
  /// @notice Mapping from underlying community token => deployed AgoraSpace
  mapping(address => address) public spaces;

  /// @notice Emitted when a new Agora Space is created
  event SpaceCreated(address indexed token, address indexed space, address indexed agoraToken);

  /// @notice Errors
  error Unauthorized();
  error AlreadyExists();
  error InvalidSignature();

  /// @notice Deploy a new AgoraSpace with its AgoraToken and register it
  /// @param _signature Signed message from factory owner authorizing creation
  ///        The message is keccak256(abi.encode(creator, token, factory)) and must be eth_sign prefixed.
  /// @param _token Address of the community token to be deposited to the Space
  function createSpace(bytes memory _signature, address _token) external {
    if (spaces[_token] != address(0)) revert AlreadyExists();

    // Reconstruct signed message and verify owner authorization
    bytes32 message = prefixed(keccak256(abi.encode(msg.sender, _token, address(this))));
    if (recoverSigner(message, _signature) != owner()) revert Unauthorized();

    // Pull token metadata for nicer symbolization
    string memory tokenSymbol = IERC20Metadata(_token).symbol();
    uint8 tokenDecimals = IERC20Metadata(_token).decimals();

    // Deploy AgoraToken (reward/stake token for the Space)
    AgoraToken agoraToken = new AgoraToken(
      string(abi.encodePacked("Agora.space ", tokenSymbol, " Token")),
      "AGT",
      tokenDecimals
    );

    // Deploy Space and wire ownership
    AgoraSpace agoraSpace = new AgoraSpace(_token, address(agoraToken));
    spaces[_token] = address(agoraSpace);

    // Transfer token ownership to the Space, then Space ownership to the creator
    agoraToken.transferOwnership(address(agoraSpace));
    agoraSpace.transferOwnership(msg.sender);

    emit SpaceCreated(_token, address(agoraSpace), address(agoraToken));
  }

  /// @dev Build an eth_sign prefixed hash
  function prefixed(bytes32 _hash) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash));
  }

  /// @dev Recover signer from a 65-byte {r,s,v} signature
  function recoverSigner(bytes32 _message, bytes memory _sig) internal pure returns (address) {
    if (_sig.length != 65) revert InvalidSignature();
    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
      r := mload(add(_sig, 32))
      s := mload(add(_sig, 64))
      v := byte(0, mload(add(_sig, 96)))
    }
    return ecrecover(_message, v, r, s);
  }
}
