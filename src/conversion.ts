/**
 * Utility method to convert base64 to Uint8Array
 */
export function b64DecodeBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const result = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    result[i] = binaryString.charCodeAt(i);
  }
  return result;
}

/**
 * Utility method to convert Uint8Array to base64
 */
export function b64EncodeBytes(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
