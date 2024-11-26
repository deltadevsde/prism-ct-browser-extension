import { b64DecodeBytes, b64EncodeBytes } from "./conversion";
import { CTLogClient } from "./ct_log_client";
import { CtLogStore } from "./ct_log_store";
import { leafHashForPreCert, sctsFromCertDer } from "./ct_parsing";
import { validateProof } from "./ct_proof_validation";
import { DomainVerificationStore } from "./verification_store";

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function run_node() {
  // TODO: Replace with actually running a prism light node
  let i = 0;
  while (true) {
    await sleep(5000);
    i += 1;
    console.log(`Node is still running ... ${i}`);
  }
}

run_node();

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
        const b64LogId = b64EncodeBytes(new Uint8Array(sct.logId));
        const log = ctLogStore.getLogById(b64LogId);

        if (log === undefined) {
          console.log("CT Log", b64LogId, "not found");
          return;
        }
        console.log("Cert in", log.url);
        const leafHash = await leafHashForPreCert(
          certDer,
          issuerDer,
          sct.timestamp,
          new Uint8Array(sct.extensions),
        );
        const b64LeafHash = b64EncodeBytes(leafHash);
        console.log(log.description, "B64 Leaf Hash:", b64LeafHash);

        const ctClient = new CTLogClient(log.url);

        // TODO: Acquire that from prism instead
        const logSth = await ctClient.getSignedTreeHead();

        const proof = await ctClient.getProofByHash(
          b64LeafHash,
          logSth.tree_size,
        );

        const expectedRootHash = b64DecodeBytes(logSth.sha256_root_hash);
        const verificationResult = await validateProof(
          proof,
          leafHash,
          expectedRootHash,
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
