import { HttpClient } from "./http_client";
import { PrismAccount, PrismProof } from "./prism_types";

/**
 * Response type for Prism account operations containing
 * the account details and associated proof.
 */
interface PrismAccountResponse {
  account?: PrismAccount;
  proof: PrismProof;
}

/**
 * Response type for retrieving the current commitment value
 * from the Prism system.
 */
interface PrismCommitmentResponse {
  commitment: string;
}

/**
 * Client for interacting with the Prism API endpoints.
 * Extends base HTTP client with Prism-specific operations.
 */
export class PrismClient extends HttpClient {
  /**
   * Retrieves a Prism account by its ID along with associated proof.
   *
   * @param accountId - Unique identifier for the account to retrieve
   * @returns Promise containing the account (if found) and proof
   * @throws Will throw an error if the request fails or returns invalid data
   */
  async getAccount(accountId: string): Promise<PrismAccountResponse> {
    const body = {
      id: accountId,
    };
    return await this.postJson("/get-account", body);
  }

  /**
   * Gets the current cryptographic commitment value from the Prism system.
   *
   * @returns Promise containing the current commitment string
   * @throws Will throw an error if the request fails or returns invalid data
   */
  async getCommitment(): Promise<PrismCommitmentResponse> {
    return await this.fetchJson("/get-current-commitment");
  }
}
