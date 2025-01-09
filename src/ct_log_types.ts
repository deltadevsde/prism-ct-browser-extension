export interface CtUsableState {
  timestamp: string;
}

export interface CtReadonlyState {
  timestamp: string;
  final_tree_head: {
    sha256_root_hash: string;
    tree_size: number;
  };
}

export interface CtRetiredState {
  timestamp: string;
}

export interface CtLogState {
  usable?: CtUsableState;
  readonly?: CtReadonlyState;
  retired?: CtRetiredState;
}

export interface CtTemporalInterval {
  start_inclusive: string;
  end_exclusive: string;
}

export interface CtLog {
  description: string;
  log_id: string;
  key: string;
  url: string;
  mmd: number;
  state: CtLogState;
  temporal_interval?: CtTemporalInterval;
}

export interface CtLogOperator {
  name: string;
  email: string[];
  logs: CtLog[];
  tiled_logs: any[]; // unknown
}

export interface CtLogList {
  version: string;
  log_list_timestamp: string;
  operators: CtLogOperator[];
}

export interface CtMerkleProof {
  leaf_index: number;
  audit_path: string[];
}

export interface CtLogEntry {
  leaf_input: string;
  extra_data: string;
}

export interface CtSignedTreeHead {
  version: number;
  signatureType: number;
  timestamp: number;
  treeSize: number;
  rootHash: Uint8Array;
}
