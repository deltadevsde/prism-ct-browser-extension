interface CtUsableState {
  timestamp: string;
}

interface CtReadonlyState {
  timestamp: string;
  final_tree_head: {
    sha256_root_hash: string;
    tree_size: number;
  };
}

interface CtRetiredState {
  timestamp: string;
}

interface CtLogState {
  usable?: CtUsableState;
  readonly?: CtReadonlyState;
  retired?: CtRetiredState;
}

interface CtTemporalInterval {
  start_inclusive: string;
  end_exclusive: string;
}

interface CtLog {
  description: string;
  log_id: string;
  key: string;
  url: string;
  mmd: number;
  state: CtLogState;
  temporal_interval?: CtTemporalInterval;
}

interface CtLogOperator {
  name: string;
  email: string[];
  logs: CtLog[];
  tiled_logs: any[]; // unknown
}

interface CtLogList {
  version: string;
  log_list_timestamp: string;
  operators: CtLogOperator[];
}

interface CtMerkleProof {
  leaf_index: number;
  audit_path: string[];
}

interface CtLogEntry {
  leaf_input: string;
  extra_data: string;
}

interface CtSignedTreeHead {
  tree_size: number;
  timestamp: number;
  sha256_root_hash: string;
  tree_head_signature: string;
}
