/**
 * Converts a base64 encoded string to a Uint8Array of bytes.
 *
 * @param base64 - The base64 encoded string to convert
 * @returns A Uint8Array containing the decoded bytes
 * @example
 * ```typescript
 * const bytes = b64DecodeBytes('SGVsbG8gV29ybGQ=');
 * // bytes is Uint8Array(11) [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
 * ```
 */
export function base64ToBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const result = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    result[i] = binaryString.charCodeAt(i);
  }
  return result;
}

/**
 * Converts a Uint8Array of bytes to a base64 encoded string.
 *
 * @param bytes - The Uint8Array of bytes to encode
 * @returns The base64 encoded string representation
 * @example
 * ```typescript
 * const base64 = b64EncodeBytes(new Uint8Array([72, 101, 108, 108, 111]));
 * // base64 is 'SGVsbG8='
 * ```
 */
export function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Converts a hexadecimal string to a byte array (Uint8Array).
 * Handles strings with or without '0x' prefix.
 *
 * @param hexString - The hexadecimal string to convert (with or without '0x' prefix)
 * @returns A Uint8Array containing the converted bytes
 * @throws {Error} If the input string contains invalid hexadecimal characters
 * @example
 * ```typescript
 * const bytes = hexToBytes('0x48656c6c6f');
 * // bytes is Uint8Array(5) [72, 101, 108, 108, 111]
 * ```
 */
export function hexToBytes(hexString: string): Uint8Array {
  // Remove '0x' prefix if present and convert to uppercase
  const normalizedHex = hexString.replace(/^0x/i, "").toUpperCase();

  // Validate the hex string
  if (!/^[0-9A-F]*$/.test(normalizedHex)) {
    throw new Error("Invalid hexadecimal string");
  }

  // Ensure even length by padding with leading zero if necessary
  const paddedHex =
    normalizedHex.length % 2 ? "0" + normalizedHex : normalizedHex;

  // Convert hex string to byte array
  const bytes = new Uint8Array(paddedHex.length / 2);

  for (let i = 0; i < paddedHex.length; i += 2) {
    bytes[i / 2] = parseInt(paddedHex.substr(i, 2), 16);
  }

  return bytes;
}

/**
 * Converts a byte array to a hexadecimal string representation.
 * Optionally includes '0x' prefix.
 *
 * @param bytes - The byte array to convert to hexadecimal
 * @param prefix - Whether to include '0x' prefix in the output (default: false)
 * @returns The hexadecimal string representation of the byte array
 * @example
 * ```typescript
 * const hex = bytesToHex(new Uint8Array([72, 101, 108]), true);
 * // hex is '0x486c6c'
 * ```
 */
export function bytesToHex(bytes: Uint8Array, prefix: boolean = false): string {
  const hex = Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return prefix ? "0x" + hex : hex;
}

/**
 * Converts a Uint8Array of bytes to an array of individual bits.
 * Bits are arranged from most significant bit (MSB) to least significant bit (LSB).
 *
 * @param uint8Array - The byte array to convert to bits
 * @returns A Uint8Array where each element is a single bit (0 or 1)
 * @example
 * ```typescript
 * const bits = bytesToBits(new Uint8Array([5]));
 * // bits is Uint8Array(8) [0, 0, 0, 0, 0, 1, 0, 1]
 * ```
 */
export function bytesToBits(uint8Array: Uint8Array): Uint8Array {
  const bits = new Uint8Array(uint8Array.length * 8);
  for (let i = 0; i < uint8Array.length; i++) {
    const byte = uint8Array[i];
    for (let j = 0; j < 8; j++) {
      // Fill from left to right (MSB to LSB)
      bits[i * 8 + j] = (byte >> (7 - j)) & 1;
    }
  }
  return bits;
}

/**
 * Converts a number to its binary representation as an array of bits.
 * The number is treated as a 64-bit value and converted to 64 bits.
 *
 * @param num - The number to convert to bits
 * @returns A Uint8Array where each element is a single bit (0 or 1)
 * @example
 * ```typescript
 * const bits = numberToBits(5);
 * // bits represents the 64-bit binary form of 5
 * ```
 */
export function numberToBits(num: number): Uint8Array {
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    bytes[i] = (num >> (56 - i * 8)) & 0xff;
  }
  return bytesToBits(bytes);
}
