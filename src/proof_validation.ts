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

const CT_NODE_PREFIX = new Uint8Array([0x01]);

const PRISM_LEAF_DOMAIN_SEPARATOR = new Uint8Array([
  74, 77, 84, 58, 58, 76, 101, 97, 102, 78, 111, 100, 101,
]);
const PRISM_INTERNAL_DOMAIN_SEPARATOR = new Uint8Array([
  74, 77, 84, 58, 58, 73, 110, 116, 114, 110, 97, 108, 78, 111, 100, 101,
]);

/**
 * Validates a Merkle proof from a CT log server
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

    console.log(
      "Comparing hashes",
      bytesToHex(calculatedRootHash),
      bytesToHex(expectedRootHash),
    );

    return areArraysEqual(calculatedRootHash, expectedRootHash);
  } catch (error) {
    console.error("Error validating Merkle proof:", error);
    return false;
  }
}

/**
 * Validates a Merkle proof from a CT log server
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

    console.log(
      "Comparing hashes",
      bytesToHex(calculatedRootHash),
      bytesToHex(expectedRootHash),
    );

    return areArraysEqual(calculatedRootHash, expectedRootHash);
  } catch (error) {
    console.error("Error validating Merkle proof:", error);
    return false;
  }
}

async function calculateRootHash(
  leafHash: Uint8Array,
  bits: Uint8Array,
  siblingHashes: Uint8Array[],
  hashPrefix: Uint8Array,
): Promise<Uint8Array> {
  let currentHash = leafHash;

  console.log(
    "Calculating Root hash",
    bytesToHex(leafHash),
    bits,
    siblingHashes.map((a) => bytesToHex(a)),
  );
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
