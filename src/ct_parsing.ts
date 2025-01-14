import { AsnParser, AsnSerializer, OctetString } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import {
  CertificateTransparency,
  SignedCertificateTimestamp,
  id_certificateTransparency,
} from "@peculiar/asn1-cert-transparency";
import { CtSignedTreeHead } from "./ct_log_types";
import { sha256 } from "./hashing";

const MAX_UINT16 = 0xffff;

const SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2";

/**
 * Extracts Signed Certificate Timestamps (SCTs) from a certificate's DER encoding.
 *
 * @param certDer - The DER-encoded X.509 certificate as a Uint8Array
 * @returns Array of SignedCertificateTimestamp objects parsed from the certificate's SCT extension
 */
export function sctsFromCertDer(
  certDer: Uint8Array,
): SignedCertificateTimestamp[] {
  const cert = AsnParser.parse(certDer, Certificate);

  const sctExtensionBytes =
    cert.tbsCertificate.extensions?.find((ext) => ext.extnID === SCT_LIST_OID)
      ?.extnValue ?? new OctetString();

  return AsnParser.parse(sctExtensionBytes, CertificateTransparency).items;
}

/**
 * Parses a Certificate Transparency Signed Tree Head (STH) from its binary representation.
 *
 * @param bytes - The binary STH data as a Uint8Array
 * @returns A parsed CtSignedTreeHead object containing version, signature type, timestamp, tree size and root hash
 */
export function sthFromBytes(bytes: Uint8Array): CtSignedTreeHead {
  const view = new DataView(bytes.buffer, 0, bytes.length);
  const version = view.getUint8(0);
  const signatureType = view.getUint8(1);
  const timestamp = Number(view.getBigUint64(2));
  const treeSize = Number(view.getBigUint64(10));
  const rootHash = bytes.slice(18, 50);

  return {
    version,
    signatureType,
    timestamp,
    treeSize,
    rootHash,
  };
}

/**
 * Generates the binary format of a Certificate Transparency log entry for a precertificate.
 * Follows the format specified in RFC6962 section 3.2.
 *
 * @param certDer - The DER-encoded precertificate as a Uint8Array
 * @param issuerDer - The DER-encoded issuer certificate as a Uint8Array
 * @param sct_time - The timestamp to use in the SCT
 * @param sct_extensions - SCT extensions data as a Uint8Array
 * @returns Promise resolving to a Uint8Array containing the formatted log entry bytes
 * @throws Will log error if SCT extensions exceed MAX_UINT16 or if issuer key hash length is incorrect
 */
export async function logEntryBytesForPreCert(
  certDer: Uint8Array,
  issuerDer: Uint8Array,
  sct_time: Date,
  sct_extensions: Uint8Array,
): Promise<Uint8Array> {
  if (sct_extensions.length > MAX_UINT16) {
    console.error("SCT extensions oversized", sct_extensions.length);
  }

  const cert = AsnParser.parse(certDer, Certificate);

  cert.tbsCertificate.extensions = cert.tbsCertificate.extensions?.filter(
    (ext) => ext.extnID !== id_certificateTransparency,
  );
  const tbsCertBytes = new Uint8Array(
    AsnSerializer.serialize(cert.tbsCertificate),
  );

  const issuerCert = AsnParser.parse(issuerDer, Certificate);
  const issuerPublicKey = AsnSerializer.serialize(
    issuerCert.tbsCertificate.subjectPublicKeyInfo,
  );

  const issuerKeyHash = new Uint8Array(await sha256(issuerPublicKey));

  if (issuerKeyHash.length !== 32) {
    console.error("Issuer hash length incorrect", issuerKeyHash.length);
  }

  // MerkleTreeLeaf structure for X509 entry
  const version = 0;
  const leafType = 0;
  const entryType = 1;
  const timestamp = BigInt(sct_time.getTime()); // microseconds

  // Calculate total length: 1 + 1 + 8 + 2 + 32 + 3 + tbs.length + 2 +
  const leafBytes = new Uint8Array(
    47 + tbsCertBytes.length + 2 + sct_extensions.length,
  );

  let offset = 0;

  const view = new DataView(leafBytes.buffer, 0);

  leafBytes[offset++] = version;
  leafBytes[offset++] = leafType;

  // Timestamp (8 bytes)
  view.setBigUint64(offset, timestamp); // timestamp from SCT
  offset += 8;

  // Entry type (2 bytes)
  view.setUint16(offset, entryType);
  offset += 2;

  // Issuer key hash (32 bytes)
  leafBytes.set(issuerKeyHash, offset);
  offset += issuerKeyHash.length;

  // TBS length (3 bytes)
  leafBytes[offset++] = (tbsCertBytes.length >> 16) & 0xff;
  leafBytes[offset++] = (tbsCertBytes.length >> 8) & 0xff;
  leafBytes[offset++] = tbsCertBytes.length & 0xff;

  // TBS
  leafBytes.set(tbsCertBytes, offset);
  offset += tbsCertBytes.length;

  // SCT extensions length (2 bytes)
  view.setUint16(offset, sct_extensions.length);
  offset += 2;

  // SCT extensions
  leafBytes.set(sct_extensions, offset);
  offset += sct_extensions.length;

  // Prepend 0x00 as specified in RFC6962, section 2.1
  return new Uint8Array([0x00, ...leafBytes]);
}
