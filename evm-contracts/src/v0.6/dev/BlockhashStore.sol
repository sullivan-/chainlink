pragma solidity 0.6.2;

/**
 * @title BlockhashStore
 * @notice This contract provides a way to access blockhashes older than
 * the 256 block limit imposed by the BLOCKHASH opcode.
 * You may assume that any blockhash stored by the contract is correct.
 */
contract BlockhashStore {

  mapping(uint => bytes32) internal s_blockhashes;

  /**
   * @notice stores blockhash of a given block, assuming it is available through BLOCKHASH
   * @param n the number of the block whose blockhash should be stored
   */
  function store(uint256 n) public {
    bytes32 h = blockhash(n);
    require(h != 0x0, "blockhash(n) failed");
    s_blockhashes[n] = h;
  }


  /**
   * @notice stores blockhash of the earliest block still available through BLOCKHASH.
   */
  function storeEarliest() external {
    store(block.number - 256);
  }

  /**
   * @notice stores blockhash after verifying blockheader of child/subsequent block
   * @param n the number of the block whose blockhash should be stored
   * @param header the rlp-encoded blockheader of block n+1. We verify its correctness by checking
   * that it hashes to a stored blockhash, and then extract parentHash to get the n-th blockhash.
   */
  function storeVerifyHeader(uint256 n, bytes memory header) public {
    require(keccak256(header) == s_blockhashes[n + 1], "header has unknown blockhash");

    // At this point, we know that header is the correct blockheader for block n+1.

    // The header is an rlp-encoded list. The head item of that list is the 32-byte blockhash of the parent block.
    // Based on how rlp works, we know that blockheaders always have the following form:
    // 0xf9____a0PARENTHASH...
    //   ^ ^   ^
    //   | |   |
    //   | |   +--- PARENTHASH is 32 bytes. rlpenc(PARENTHASH) is 0xa || PARENTHASH.
    //   | |
    //   | +--- 2 bytes containing the sum of the lenghts of the encoded list items
    //   |
    //   +--- 0xf9 because we have a list and (sum of lengths of encode list items) fits exactly into two bytes.
    //
    // As a consequence, the PARENTHASH is always at offset 4 of the rlp-encoded block header.

    // assert(header[0] == 0xf9 && header[3] == 0xa0);
    bytes32 parentHash;
    assembly {
      parentHash := mload(add(header, 36)) // 36 = 32 byte offset at beginning of array + 4 byte offset of PARENTHASH
    }

    s_blockhashes[n] = parentHash;
  }

  function getBlockhash(uint256 number) external view returns (bytes32) {
    return s_blockhashes[number];
  }
}
