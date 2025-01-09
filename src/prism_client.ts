import { HttpClient } from "./http_client";
import { PrismAccount, PrismProof } from "./prism_types";

interface PrismAccountResponse {
  account?: PrismAccount;
  proof: PrismProof;
}

interface PrismCommitmentResponse {
  commitment: string;
}

export class PrismClient extends HttpClient {
  async getAccount(accountId: string): Promise<PrismAccountResponse> {
    const body = {
      id: accountId,
    };
    return await this.postJson("/get-account", body);
  }

  async getCommitment(): Promise<PrismCommitmentResponse> {
    return await this.fetchJson("/get-current-commitment");
  }
}
