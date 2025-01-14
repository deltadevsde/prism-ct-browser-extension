import { SignedCertificateTimestamp } from "@peculiar/asn1-cert-transparency";
import { base64ToBytes, bytesToBase64 } from "./conversion";
import { CTLogClient } from "./ct_log_client";
import { CtLogStore } from "./ct_log_store";
import { CtLog, CtSignedTreeHead } from "./ct_log_types";
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

browser.webRequest.onHeadersReceived.addListener(
  async function (details) {
    if (details.url === CtLogStore.LOG_LIST_URL) {
      // Avoid deadlock for log list URL
      return;
    }

    const domain = new URL(details.url).origin;
    const certs = await extractCertificates(details);

    // Abort early if we were not able to extract certificate data from the web request
    if (!certs) return;

    // Initialize stores
    const ctLogStore = await CtLogStore.getInstance();
    const domainVerificationStore = await DomainVerificationStore.getInstance();

    // Reset all previous verifications for the domain of the web request
    await domainVerificationStore.clearVerificationForDomain(domain);

    // Extract Signed Certificate Timestamps (SCTs) from the raw certificate.
    // Each SCT contains information about when a certificate transparency log
    // observed and logged the certificate, signed by the log's private key
    const scts = sctsFromCertDer(certs.certDer);

    // Go through all SCTs we found in the certificate, and verify them against their
    // corresponding CT logs using proof validation
    for (const sct of scts) {
      const b64LogId = bytesToBase64(new Uint8Array(sct.logId));
      const log = ctLogStore.getLogById(b64LogId);

      if (log === undefined) {
        console.warn("CT Log", b64LogId, "not found in official list");
        continue;
      }

      try {
        // Fetch the latest Signed Tree Head (STH) of the CT Log mentioned in the SCT.
        // An STH is a cryptographic commitment to the current state of a log,
        // signed by the log operator, that includes a root hash and timestamp.
        const sth = await queryLogSth(log);

        // After ensuring the STH is valid, we can now check whether
        // an entry with the cert's content really exists in the CT Log
        const isCtLogEntryValid = await checkCertValidity(
          certs.certDer,
          certs.issuerDer,
          sct,
          log,
          sth,
        );

        // In the end, we store the validation result for the corresponding
        // (domain, log) pair.
        await domainVerificationStore.reportLogVerification(
          domain,
          log.description,
          isCtLogEntryValid,
        );
      } catch (error) {
        console.error(error);
        // In the end, we store the validation result for the corresponding
        // (domain, log) pair.
        await domainVerificationStore.reportLogVerification(
          domain,
          log.description,
          false,
        );
        return;
      }
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

run_node();

const prism = new PrismClient("http://127.0.0.1:50524");

/**
 * Utility function to pause execution for a specified number of milliseconds
 * @param ms Number of milliseconds to sleep
 * @returns Promise that resolves after the specified delay
 */
async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Runs a simulated prism light node
 * Currently just a placeholder that logs periodic messages
 * TODO: Replace with actual prism light node implementation
 */
async function run_node() {
  let i = 0;
  while (true) {
    await sleep(60000);
    i += 1;
    console.log(`Node is still running ...`);
  }
}

/**
 * Extracts certificate and issuer certificate from a web request
 * @param details Web request details containing security information
 * @returns Object containing certificate DER and issuer DER, or null if certificates cannot be extracted
 */
async function extractCertificates(details) {
  const securityInfo = await browser.webRequest.getSecurityInfo(
    details.requestId,
    { certificateChain: true, rawDER: true },
  );

  if (securityInfo.state !== "secure" && securityInfo.state !== "weak") {
    // Non-HTTPS requests can't be verified
    return null;
  }

  if (securityInfo.certificates.length < 2) {
    // 0 = No certificate at all - error
    // 1 = No issuer (e.g. self signed) - can't query CT log
    return null;
  }

  return {
    certDer: new Uint8Array(securityInfo.certificates[0].rawDER),
    issuerDer: new Uint8Array(securityInfo.certificates[1].rawDER),
  };
}

/**
 * Queries and validates a Certificate Transparency log's Signed Tree Head from prism.
 *
 * We use prism accounts instead of asking the log directly because the log can be dishonest
 * and lead you to believe a certificate is valid and has been included, even if it hasn't.
 * By posting the STHs to a prism account, we have a verifiable append-only ledger that all users
 * can access in a trust minimized way to get the same view of the STH. This bypasses the
 * need for gossip-based methods and heavy clients.
 *
 * @param log The CtLog from which the STH shall be queried
 * @returns Parsed Signed Tree Head from the log
 * @throws Error if log not found in Prism or proof validation fails
 */
async function queryLogSth(log: CtLog) {
  // Here, we fetch the Account for a specific CT Log from prism
  const accountRes = await prism.getAccount(log.log_id);

  if (accountRes.account === undefined || accountRes.proof.leaf === undefined) {
    throw new Error(`CT Log ${log.log_id} not found in prism`);
  }

  if (accountRes.account.signed_data.length != 1) {
    throw new Error(
      `Incorrect number of prism entries (${accountRes.account.signed_data.length}) for Log ${log.log_id}`,
    );
  }

  // In order to validate the aquired account info, we need the latest cryptographic commitment
  // from prism.
  // TODO: query commitment from light node instead of via REST
  const expectedPrismRootHashHex = (await prism.getCommitment()).commitment;
  const prismProof = accountRes.proof;
  // To ensure that prism gave us the correct account data (and thus STH)
  // we need to serialize the account like prism does.
  const prismValue = prismAccountToBincode(accountRes.account);

  // We are then able to validate the Merkle Proof provided by prism.
  // If successfully verified, we can be sure that the STH we fetched,
  // is the one agreed upon by all prism nodes.
  const isPrismProofValid = await validatePrismProof(
    prismProof,
    log.log_id,
    prismValue,
    expectedPrismRootHashHex,
  );

  if (!isPrismProofValid) {
    throw new Error(`Invalid Prism proof for log ${log.log_id}`);
  }

  return sthFromBytes(base64ToBytes(accountRes.account.signed_data[0].data));
}

/**
 * Verifies a Certificate Transparency log proof for a certificate.
 *
 * @param certDer Certificate in DER format
 * @param issuerDer Issuer certificate in DER format
 * @param sct Signed Certificate Timestamp
 * @param log CT log information
 * @param sth Signed Tree Head from the log
 * @returns Boolean indicating if the proof is valid
 */
async function checkCertValidity(
  certDer: Uint8Array,
  issuerDer: Uint8Array,
  sct: SignedCertificateTimestamp,
  log: CtLog,
  sth: CtSignedTreeHead,
) {
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

  return await validateCtProof(ctProof, leafHash, sth.rootHash);
}
