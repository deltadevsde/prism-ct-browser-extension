import { base64ToBytes, bytesToBase64 } from "./conversion";
import { CTLogClient } from "./ct_log_client";
import { CtLogStore } from "./ct_log_store";
import {
  logEntryBytesForPreCert,
  sctsFromCertDer,
  sthFromBytes,
} from "./ct_parsing";
import { sha256 } from "./hashing";
import { PrismClient } from "./prism_client";
import { prismAccountToBincode } from "./prism_serialization";
import { validateCtProof, validatePrismProof } from "./proof_validation";
import { DomainVerificationStore } from "./verification_store";

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function run_node() {
  // TODO: Replace with actually running a prism light node
  let i = 0;
  while (true) {
    await sleep(60000);
    i += 1;
    console.log(`Node is still running ...`);
  }
}

run_node();

const prism = new PrismClient("http://127.0.0.1:50524");

browser.webRequest.onHeadersReceived.addListener(
  async function (details) {
    if (details.url === CtLogStore.LOG_LIST_URL) {
      // Avoid deadlock for log list URL
      return;
    }

    const domain = new URL(details.url).origin;

    try {
      const securityInfo = await browser.webRequest.getSecurityInfo(
        details.requestId,
        { certificateChain: true, rawDER: true },
      );

      if (securityInfo.state !== "secure" && securityInfo.state !== "weak") {
        // Non-HTTPS requests can't be verified
        return;
      }

      if (securityInfo.certificates.length < 2) {
        // 0 = No certificate at all - error
        // 1 = No issuer (e.g. self signed) - can't query CT log
        return;
      }

      const certDer = new Uint8Array(securityInfo.certificates[0].rawDER);
      const issuerDer = new Uint8Array(securityInfo.certificates[1].rawDER);

      const ctLogStore = await CtLogStore.getInstance();

      const domainVerificationStore =
        await DomainVerificationStore.getInstance();
      await domainVerificationStore.clearVerificationForDomain(domain);

      const scts = sctsFromCertDer(certDer);

      for (const sct of scts) {
        const b64LogId = bytesToBase64(new Uint8Array(sct.logId));
        const log = ctLogStore.getLogById(b64LogId);

        if (log === undefined) {
          console.log("CT Log", b64LogId, "not found in official list");
          return;
        }
        console.log("Cert in", log.url);

        // Get latest CT-Log Merkle root from prism node
        const accountRes = await prism.getAccount(log.log_id);
        if (
          accountRes.account === undefined ||
          accountRes.proof.leaf === undefined
        ) {
          console.error("CT Log", b64LogId, "not found in prism");
          return;
        }

        if (accountRes.account.signed_data.length != 1) {
          console.error(
            "Incorrect number of prism entries (",
            accountRes.account.signed_data.length,
            ") for Log",
            b64LogId,
          );
          return;
        }

        // TODO: Does signed_data.key need to be checked?
        const expectedPrismRootHashHex = (await prism.getCommitment())
          .commitment;

        // Validate prism Merkle proof
        // (ensures that prism truly returned the correct CT-Log merkle root)
        const prismProof = accountRes.proof;
        const prismValue = prismAccountToBincode(accountRes.account);

        const isPrismProofValid = await validatePrismProof(
          prismProof,
          log.log_id,
          prismValue,
          expectedPrismRootHashHex,
        );

        // When prism proof fails, return early
        if (!isPrismProofValid) {
          await domainVerificationStore.reportLogVerification(
            domain,
            log.description,
            isPrismProofValid,
          );
          return;
        }

        const b64Sth = accountRes.account.signed_data[0].data;
        const bytesSth = base64ToBytes(b64Sth);
        const sth = sthFromBytes(bytesSth);

        // Verify that a CT-Log entry exists for the SCT

        // Construct the correct hash to query a CT-Log entry Merkle proof
        const logEntryBytes = await logEntryBytesForPreCert(
          certDer,
          issuerDer,
          sct.timestamp,
          new Uint8Array(sct.extensions),
        );
        const leafHash = await sha256(logEntryBytes);

        const ctClient = new CTLogClient(log.url);

        const ctProof = await ctClient.getProofByHash(
          bytesToBase64(leafHash),
          sth.treeSize,
        );

        // Validate CT-Log Merkle proof
        // (ensures that the certificate of the request is actually the one submitted to the CT-log)
        const verificationResult = await validateCtProof(
          ctProof,
          leafHash,
          sth.rootHash,
        );

        await domainVerificationStore.reportLogVerification(
          domain,
          log.description,
          verificationResult,
        );
      }
    } catch (error) {
      console.error("Error validating cert:", error);
    }

    return {};
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["blocking"],
);

browser.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
  const domain = new URL(request.url).origin;
  if (request.action === "getDomainVerification") {
    const verificationStore = await DomainVerificationStore.getInstance();
    return await verificationStore.verificationForDomain(domain);
  }
});
