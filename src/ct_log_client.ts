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

/**
 * Client for interacting with a Certificate Transparency log server
 * Implements the CT Log v1 protocol specification
 */
export class CTLogClient extends HttpClient {
  /**
   * Retrieves the latest Signed Tree Head from the log
   * @returns Promise resolving to the Signed Tree Head response
   * @throws If the request fails or returns invalid data
   */
  async getSignedTreeHead(): Promise<CtSignedTreeHeadResponse> {
    return await this.fetchJson("/ct/v1/get-sth", {});
  }

  /**
   * Gets a Merkle proof for a log entry
   * @param b64entryHash Base64 encoded hash of the log entry to get proof for
   * @param treeSize Size of the tree to get the proof against
   * @returns Promise resolving to a Merkle proof for the entry
   * @throws If the request fails or returns invalid data
   */
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

  /**
   * Retrieves a range of entries from the log
   * @param start Index of first entry to retrieve (inclusive)
   * @param end Index of last entry to retrieve (inclusive)
   * @returns Promise resolving to the requested log entries
   * @throws If the request fails or returns invalid data
   */
  async getEntries(start: number, end: number): Promise<CtEntriesResponse> {
    const params = {
      start,
      end,
    };
    return await this.fetchJson("/ct/v1/get-entries", params);
  }
}
