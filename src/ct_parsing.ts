import { AsnParser, AsnSerializer, OctetString } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import {
  CertificateTransparency,
  id_certificateTransparency,
  SignedCertificateTimestamp,
} from "@peculiar/asn1-cert-transparency";
import { CtSignedTreeHead } from "./ct_log_types";

const SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2";
const MAX_UINT16 = 0xffff;

export function sctsFromCertDer(
  certDer: Uint8Array,
): SignedCertificateTimestamp[] {
  const cert = AsnParser.parse(certDer, Certificate);

  const sctExtensionBytes =
    cert.tbsCertificate.extensions?.find((ext) => ext.extnID === SCT_LIST_OID)
      ?.extnValue ?? new OctetString();

  return AsnParser.parse(sctExtensionBytes, CertificateTransparency).items;
}

export async function leafHashForPreCert(
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

  const issuerKeyHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", issuerPublicKey),
  );

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
  const preimage = new Uint8Array([0, ...leafBytes]);
  const hash = await crypto.subtle.digest("SHA-256", preimage);

  return new Uint8Array(hash);
}
