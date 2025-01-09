import { CtLogEntry, CtMerkleProof } from "./ct_log_types";
import { HttpClient } from "./http_client";

interface CtEntriesResponse {
  entries: CtLogEntry[];
}

export interface CtSignedTreeHeadResponse {
  tree_size: number;
  timestamp: number;
  sha256_root_hash: string;
  tree_head_signature: string;
}

export class CTLogClient extends HttpClient {
  async getSignedTreeHead(): Promise<CtSignedTreeHeadResponse> {
    return await this.fetchJson("/ct/v1/get-sth", {});
  }

  async getProofByHash(
    b64entryHash: string,
    treeSize: number,
  ): Promise<CtMerkleProof> {
    const params = {
      hash: b64entryHash,
      tree_size: treeSize,
    };
    return await this.fetchJson("/ct/v1/get-proof-by-hash", params);
  }

  async getEntries(start: number, end: number): Promise<CtEntriesResponse> {
    const params = {
      start,
      end,
    };
    return await this.fetchJson("/ct/v1/get-entries", params);
  }
}
