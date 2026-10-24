import assert from "node:assert/strict";
import test from "node:test";

import { decodeBase64Url, encodeBase64Url } from "./encoding.mjs";

test("base64url round-trips bytes without padding", () => {
  const input = Uint8Array.from([0, 1, 2, 253, 254, 255]);
  const encoded = encodeBase64Url(input);
  assert.equal(encoded, "AAEC_f7_");
  assert.deepEqual(decodeBase64Url(encoded), input);
});

test("base64url rejects padding, non-alphabet characters, and impossible lengths", () => {
  for (const input of ["AA==", "AA+_", "A", ""]) {
    assert.throws(() => decodeBase64Url(input), TypeError);
  }
});

test("base64url decoder requires canonical trailing bits", () => {
  assert.throws(() => decodeBase64Url("AB"), /Non-canonical/u);
});
