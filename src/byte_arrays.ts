/**
 * Concatenates multiple Uint8Arrays into a single Uint8Array.
 *
 * @param arrays - Variable number of Uint8Array arguments to concatenate
 * @returns A new Uint8Array containing all input arrays concatenated in order
 * @example
 * ```ts
 * const arr1 = new Uint8Array([1, 2]);
 * const arr2 = new Uint8Array([3, 4]);
 * const result = concatenateArrays(arr1, arr2);
 * // result is Uint8Array([1, 2, 3, 4])
 * ```
 */
export function concatenateArrays(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;

  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/**
 * Compares two Uint8Arrays for equality by checking length and values.
 *
 * @param arr1 - First Uint8Array to compare
 * @param arr2 - Second Uint8Array to compare
 * @returns true if arrays are equal in length and values, false otherwise
 * @example
 * ```ts
 * const arr1 = new Uint8Array([1, 2]);
 * const arr2 = new Uint8Array([1, 2]);
 * const equal = areArraysEqual(arr1, arr2); // true
 * ```
 */
export function areArraysEqual(arr1: Uint8Array, arr2: Uint8Array): boolean {
  if (arr1.length !== arr2.length) {
    return false;
  }
  return arr1.every((value, index) => value === arr2[index]);
}
