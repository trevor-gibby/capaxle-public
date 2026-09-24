import { Buffer } from "node:buffer";

/** Strict canonical unpadded base64url decoding for 256-bit security values. */
export function decodeCanonicalBase64Url256(value: unknown): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value))
    throw new TypeError("Invalid canonical 256-bit base64url value.");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value)
    throw new TypeError("Invalid canonical 256-bit base64url value.");
  return bytes;
}
