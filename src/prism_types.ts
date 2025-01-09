export interface PrismAccount {
  id: string;
  nonce: number;
  valid_keys: PrismCryptoPayload[];
  signed_data: PrismSignedData[];
  service_challenge?: PrismServiceChallenge;
}

export type PrismServiceChallenge = PrismSignedServiceChallenge;

export interface PrismSignedServiceChallenge {
  Signed: PrismCryptoPayload;
}

export interface PrismSignedData {
  key: PrismCryptoPayload;
  data: string; //base64 encoded bytes
}

export type PrismOperation =
  | PrismCreateAccountOperation
  | PrismAddDataOperation
  | PrismSetDataOperation;

export interface PrismCreateAccountOperation {
  CreateAccount: {
    id: string;
    service_id: string;
    challenge: PrismServiceChallengeInput;
    key: PrismCryptoPayload;
  };
}

export type PrismServiceChallengeInput = PrismServiceChallengeInputSigned;

export interface PrismServiceChallengeInputSigned {
  Signed: {
    algorithm: string;
    bytes: string;
  };
}

export interface PrismAddDataOperation {
  AddData: {
    data: string;
    data_signature?: PrismSignatureBundle;
  };
}

export interface PrismSetDataOperation {
  SetData: {
    data: string;
    data_signature?: PrismSignatureBundle;
  };
}

export interface PrismSignatureBundle {
  verifying_key: PrismCryptoPayload;
  signature: PrismCryptoPayload;
}
export enum PrismCryptoAlgorithm {
  ed25519 = "ed25519",
  secp256k1 = "secp256k1",
  secp256r1 = "secp256r1",
}

export interface PrismCryptoPayload {
  algorithm: PrismCryptoAlgorithm;
  bytes: string;
}

export interface PrismHashchainSignatureBundle {
  key_idx: number;
  signature: PrismCryptoPayload;
}

export interface PrismProof {
  leaf?: string;
  siblings: string[];
}
