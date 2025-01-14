import { areArraysEqual, concatenateArrays } from "./byte_arrays";
import {
  base64ToBytes,
  bytesToBits,
  bytesToHex,
  hexToBytes,
  numberToBits,
} from "./conversion";
import { CtMerkleProof } from "./ct_log_types";
import { sha256 } from "./hashing";
import { PrismProof } from "./prism_types";

/**
 * Prefix byte used for Certificate Transparency Merkle tree nodes
 */
const CT_NODE_PREFIX = new Uint8Array([0x01]);

/**
 * Domain separator for Prism Merkle tree leaf nodes
 * ASCII encoding of "JMT::LeafNode"
 */
const PRISM_LEAF_DOMAIN_SEPARATOR = new Uint8Array([
  74, 77, 84, 58, 58, 76, 101, 97, 102, 78, 111, 100, 101,
]);

/**
 * Domain separator for Prism Merkle tree internal nodes
 * ASCII encoding of "JMT::IntrnalNode"
 */
const PRISM_INTERNAL_DOMAIN_SEPARATOR = new Uint8Array([
  74, 77, 84, 58, 58, 73, 110, 116, 114, 110, 97, 108, 78, 111, 100, 101,
]);

/**
 * Validates a Merkle proof obtained from prism
 *
 * @param proof - The Merkle proof to validate containing leaf hash and sibling hashes
 * @param key - The key whose presence is being proven
 * @param value - The value associated with the key being proven
 * @param expectedRootHashHex - The expected root hash of the Merkle tree in hex format
 * @returns Promise<boolean> - True if the proof is valid, false otherwise
 *
 * @throws Will return false if there's an error during validation
 */
export async function validatePrismProof(
  proof: PrismProof,
  key: string,
  value: Uint8Array,
  expectedRootHashHex: string,
): Promise<boolean> {
  try {
    if (!proof.leaf) {
      console.error("Prism proof does not contain leaf hash");
      return false;
    }

    const textEncoder = new TextEncoder();
    const keyHash = await sha256(textEncoder.encode(key));
    const valueHash = await sha256(value);

    const leafHash = await sha256(
      concatenateArrays(PRISM_LEAF_DOMAIN_SEPARATOR, keyHash, valueHash),
    );
    const expectedLeafHash = hexToBytes(proof.leaf);

    if (!areArraysEqual(leafHash, expectedLeafHash)) {
      console.error("Prism leaf hashes are not equal");
      return false;
    }

    const expectedRootHash = hexToBytes(expectedRootHashHex);

    const bits = bytesToBits(keyHash)
      .reverse()
      .slice(256 - proof.siblings.length);
    const sibling_hashes = proof.siblings.map(hexToBytes);

    const calculatedRootHash = await calculateRootHash(
      leafHash,
      bits,
      sibling_hashes,
      PRISM_INTERNAL_DOMAIN_SEPARATOR,
    );

    return areArraysEqual(calculatedRootHash, expectedRootHash);
  } catch (error) {
    console.error("Error validating Merkle proof:", error);
    return false;
  }
}

/**
 * Validates a Merkle proof from a Certificate Transparency (CT) log server
 *
 * @param proof - The CT Merkle proof containing leaf index and audit path
 * @param leafHash - The hash of the leaf node being proven
 * @param expectedRootHash - The expected root hash of the Merkle tree
 * @returns Promise<boolean> - True if the proof is valid, false otherwise
 *
 * @throws Will return false if there's an error during validation
 */
export async function validateCtProof(
  proof: CtMerkleProof,
  leafHash: Uint8Array,
  expectedRootHash: Uint8Array,
): Promise<boolean> {
  try {
    const bits = numberToBits(proof.leaf_index)
      .reverse()
      .slice(0, proof.audit_path.length);
    const sibling_hashes = proof.audit_path.map(base64ToBytes);

    const calculatedRootHash = await calculateRootHash(
      leafHash,
      bits,
      sibling_hashes,
      CT_NODE_PREFIX,
    );

    return areArraysEqual(calculatedRootHash, expectedRootHash);
  } catch (error) {
    console.error("Error validating Merkle proof:", error);
    return false;
  }
}

/**
 * Calculates the root hash of a Merkle tree given a leaf hash and sibling hashes
 *
 * @param leafHash - The hash of the leaf node
 * @param bits - Bit array determining left/right positioning of siblings
 * @param siblingHashes - Array of sibling hashes needed for proof verification
 * @param hashPrefix - Domain separator prefix for hash calculations
 * @returns Promise<Uint8Array> - The calculated root hash
 *
 * Algorithm:
 * 1. Start with the leaf hash
 * 2. For each level:
 *    - If bit is 1: sibling is left, current hash is right
 *    - If bit is 0: current hash is left, sibling is right
 * 3. Hash the concatenated values with prefix
 */
async function calculateRootHash(
  leafHash: Uint8Array,
  bits: Uint8Array,
  siblingHashes: Uint8Array[],
  hashPrefix: Uint8Array,
): Promise<Uint8Array> {
  let currentHash = leafHash;

  for (let i = 0; i < siblingHashes.length; i++) {
    const siblingHash = siblingHashes[i];
    const bit = bits[i];

    // If bit is 1, sibling is on the left
    // If bit is 0, sibling is on the right
    if (bit === 1) {
      currentHash = await sha256(
        concatenateArrays(hashPrefix, siblingHash, currentHash),
      );
    } else {
      currentHash = await sha256(
        concatenateArrays(hashPrefix, currentHash, siblingHash),
      );
    }
  }

  return currentHash;
}
