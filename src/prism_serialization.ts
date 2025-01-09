import { concatenateArrays } from "./byte_arrays";
import { base64ToBytes } from "./conversion";
import {
  PrismAccount,
  PrismCryptoAlgorithm,
  PrismCryptoPayload,
  PrismServiceChallenge,
  PrismSignedData,
} from "./prism_types";

export function num64ToBincodeLe(num: number): Uint8Array {
  const buffer = new ArrayBuffer(8); // 8 bytes for 64-bit integer
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(num), true);
  return new Uint8Array(buffer);
}

function bytesToBincode(bytes: Uint8Array): Uint8Array {
  const lengthBytes = num64ToBincodeLe(bytes.length);
  return concatenateArrays(lengthBytes, bytes);
}

function stringToBincode(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return bytesToBincode(encoder.encode(str));
}

function cryptoAlgorithmToBincode(algorithm: PrismCryptoAlgorithm): Uint8Array {
  switch (algorithm) {
    case PrismCryptoAlgorithm.ed25519:
      return new Uint8Array([0, 0, 0, 0]);
    case PrismCryptoAlgorithm.secp256k1:
      return new Uint8Array([1, 0, 0, 0]);
    case PrismCryptoAlgorithm.secp256r1:
      return new Uint8Array([2, 0, 0, 0]);
    default:
      throw new Error(`Unknown crypto algorithm: ${algorithm}`);
  }
}

function cryptoPayloadToBincode(cryptoPayload: PrismCryptoPayload): Uint8Array {
  const algorithmBytes = cryptoAlgorithmToBincode(cryptoPayload.algorithm);
  const bytesBytes = bytesToBincode(base64ToBytes(cryptoPayload.bytes));

  return concatenateArrays(algorithmBytes, bytesBytes);
}

function signedDataToBincode(signedData: PrismSignedData): Uint8Array {
  const keyBytes = cryptoPayloadToBincode(signedData.key);
  const dataBytes = bytesToBincode(base64ToBytes(signedData.data));
  return concatenateArrays(keyBytes, dataBytes);
}

function serviceChallengeToBincode(
  challenge: PrismServiceChallenge,
): Uint8Array {
  return bytesToBincode(base64ToBytes(challenge.Signed.bytes));
}

export function prismAccountToBincode(account: PrismAccount): Uint8Array {
  const idBytes = stringToBincode(account.id);
  const nonceBytes = num64ToBincodeLe(account.nonce);
  const validKeysLengthBytes = num64ToBincodeLe(account.valid_keys.length);
  const validKeysBytes = account.valid_keys.map((key) =>
    cryptoPayloadToBincode(key),
  );
  const signedDataLengthBytes = num64ToBincodeLe(account.signed_data.length);
  const signedDataBytes = account.signed_data.map((data) =>
    signedDataToBincode(data),
  );

  const serviceChallengeBytes = account.service_challenge
    ? serviceChallengeToBincode(account.service_challenge)
    : new Uint8Array([0]);

  return concatenateArrays(
    idBytes,
    nonceBytes,
    validKeysLengthBytes,
    ...validKeysBytes,
    signedDataLengthBytes,
    ...signedDataBytes,
    serviceChallengeBytes,
  );
}
