/**
 * Computes the SHA-256 hash of the provided data.
 *
 * This function uses the Web Crypto API to calculate a cryptographically secure
 * SHA-256 hash of the input data. The hash is returned as a Uint8Array containing
 * 32 bytes (256 bits).
 *
 * @param data - The input data to hash. Can be any BufferSource (ArrayBuffer, TypedArray, etc)
 * @returns A Promise that resolves to a Uint8Array containing the 32-byte SHA-256 hash
 * @throws If the Web Crypto API is not available or the hashing operation fails
 *
 * @example
 * const data = new TextEncoder().encode('hello world');
 * const hash = await sha256(data);
 * console.log(Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join(''));
 */
export async function sha256(data: BufferSource): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}
