export function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodeBase64Url(value) {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new TypeError("Expected unpadded base64url data.");
  }
  if (value.length % 4 === 1) throw new TypeError("Invalid base64url length.");

  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new TypeError("Invalid base64url data.");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) throw new TypeError("Non-canonical base64url data.");
  return bytes;
}
