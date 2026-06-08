import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createPrivateKey, sign as cryptoSign } from "node:crypto";
import {
  generateExtensionSigningKeyPair,
  buildSignaturePayload,
  signExtension,
  verifyAgainstKey,
  verifyExtensionSignature,
  resolveSignatureVerdict,
  loadTrustedPublicKeys,
  publicKeyId,
  SIGNATURE_SCHEME,
} from "@/lib/extension-signature";

// Ed25519 extension signing. Proves: sign/verify round-trip,
// tamper/wrong-key rejection, the resolveSignatureVerdict policy table, env key
// loading, and that a signature built over the canonical payload format
// verifies via the host verifier (format parity with the publisher's signer).

const FIELDS = { packageName: "@cinatra-ai/signed-fixture", version: "1.2.3", integrity: "sha512-AAAA==" };

describe("extension signing — sign/verify", () => {
  it("verifies a correctly-signed payload, rejects tamper + wrong key", () => {
    const kp = generateExtensionSigningKeyPair();
    const sig = signExtension(FIELDS, kp.privateKeyPkcs8DerB64);
    expect(verifyAgainstKey(FIELDS, sig, kp.publicKeyDerB64)).toBe(true);

    // tamper each bound field
    expect(verifyAgainstKey({ ...FIELDS, version: "9.9.9" }, sig, kp.publicKeyDerB64)).toBe(false);
    expect(verifyAgainstKey({ ...FIELDS, packageName: "@evil/x" }, sig, kp.publicKeyDerB64)).toBe(false);
    expect(verifyAgainstKey({ ...FIELDS, integrity: "sha512-BBBB==" }, sig, kp.publicKeyDerB64)).toBe(false);

    // a different key does not verify
    const other = generateExtensionSigningKeyPair();
    expect(verifyAgainstKey(FIELDS, sig, other.publicKeyDerB64)).toBe(false);
    // a garbage signature/key never throws, returns false
    expect(verifyAgainstKey(FIELDS, "not-base64-sig", kp.publicKeyDerB64)).toBe(false);
    expect(verifyAgainstKey(FIELDS, sig, "not-a-key")).toBe(false);
  });

  it("payload is the documented canonical form + keyId is stable", () => {
    expect(buildSignaturePayload(FIELDS)).toBe(`${SIGNATURE_SCHEME}\n@cinatra-ai/signed-fixture\n1.2.3\nsha512-AAAA==`);
    const kp = generateExtensionSigningKeyPair();
    expect(publicKeyId(kp.publicKeyDerB64)).toBe(kp.keyId);
    expect(kp.keyId).toMatch(/^[a-f0-9]{16}$/);
  });

  it("verifyExtensionSignature accepts any one trusted key (rotation)", () => {
    const a = generateExtensionSigningKeyPair();
    const b = generateExtensionSigningKeyPair();
    const sig = signExtension(FIELDS, b.privateKeyPkcs8DerB64);
    const trusted = [
      { keyId: a.keyId, publicKeyDerB64: a.publicKeyDerB64 },
      { keyId: b.keyId, publicKeyDerB64: b.publicKeyDerB64 },
    ];
    expect(verifyExtensionSignature(FIELDS, sig, trusted)).toBe(true);
    expect(verifyExtensionSignature(FIELDS, sig, [{ keyId: a.keyId, publicKeyDerB64: a.publicKeyDerB64 }])).toBe(false);
  });
});

describe("extension signing — resolveSignatureVerdict policy", () => {
  const kp = generateExtensionSigningKeyPair();
  const trusted = [{ keyId: kp.keyId, publicKeyDerB64: kp.publicKeyDerB64 }];
  const goodSig = signExtension(FIELDS, kp.privateKeyPkcs8DerB64);

  it("no signing configured + no signature → undefined (no-op, today's behavior)", () => {
    expect(resolveSignatureVerdict({ ...FIELDS }, { trustedKeys: [], required: false })).toBeUndefined();
  });
  it("valid signature + trusted key → true", () => {
    expect(resolveSignatureVerdict({ ...FIELDS, signature: goodSig }, { trustedKeys: trusted, required: false })).toBe(true);
  });
  it("present-but-invalid signature → false (REFUSE, even if not required)", () => {
    expect(resolveSignatureVerdict({ ...FIELDS, signature: "AAAA" }, { trustedKeys: trusted, required: false })).toBe(false);
  });
  it("required + no signature → false", () => {
    expect(resolveSignatureVerdict({ ...FIELDS }, { trustedKeys: trusted, required: true })).toBe(false);
  });
  it("required + valid signature → true", () => {
    expect(resolveSignatureVerdict({ ...FIELDS, signature: goodSig }, { trustedKeys: trusted, required: true })).toBe(true);
  });
  it("signature present but no trusted key → undefined unless required (then false)", () => {
    expect(resolveSignatureVerdict({ ...FIELDS, signature: goodSig }, { trustedKeys: [], required: false })).toBeUndefined();
    expect(resolveSignatureVerdict({ ...FIELDS, signature: goodSig }, { trustedKeys: [], required: true })).toBe(false);
  });
});

describe("extension signing — env loading", () => {
  it("loadTrustedPublicKeys parses comma-separated SPKI keys + skips garbage", () => {
    const a = generateExtensionSigningKeyPair();
    const b = generateExtensionSigningKeyPair();
    const env = { CINATRA_EXTENSION_SIGNING_PUBLIC_KEYS: `${a.publicKeyDerB64}, not-a-key ,${b.publicKeyDerB64}` };
    const keys = loadTrustedPublicKeys(env);
    expect(keys.map((k) => k.keyId).sort()).toEqual([a.keyId, b.keyId].sort());
  });

  it("rejects a non-Ed25519 (RSA) key as a trust root — strictly Ed25519", () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaPubDerB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");
    // an RSA SPKI key is parseable but must NOT be loaded as a trusted key
    expect(loadTrustedPublicKeys({ CINATRA_EXTENSION_SIGNING_PUBLIC_KEYS: rsaPubDerB64 })).toEqual([]);
    // and a verify call against an RSA key fails closed (never accepts an RSA sig)
    expect(verifyAgainstKey(FIELDS, "AAAA", rsaPubDerB64)).toBe(false);
  });
});

describe("extension signing — canonical-payload ↔ host-verifier format parity", () => {
  it("a signature built over the canonical payload (independent signer) verifies via the host lib", () => {
    const kp = generateExtensionSigningKeyPair();
    // Reproduce, with raw node:crypto Ed25519, exactly what an external publisher
    // signer does: rebuild the canonical newline-delimited payload by hand (NOT via
    // buildSignaturePayload) and sign it. The host verifier accepting this proves
    // the on-the-wire payload + signature formats are interoperable.
    const payload = `${SIGNATURE_SCHEME}\n${FIELDS.packageName}\n${FIELDS.version}\n${FIELDS.integrity}`;
    const privateKey = createPrivateKey({
      key: Buffer.from(kp.privateKeyPkcs8DerB64, "base64"),
      format: "der",
      type: "pkcs8",
    });
    const signature = cryptoSign(null, Buffer.from(payload, "utf8"), privateKey).toString("base64");

    // The independently-produced signature is accepted by the HOST verifier → formats match.
    expect(verifyAgainstKey(FIELDS, signature, kp.publicKeyDerB64)).toBe(true);
    // And it agrees byte-for-byte with the lib's own signer over the same fields.
    expect(signature).toBe(signExtension(FIELDS, kp.privateKeyPkcs8DerB64));
  });
});
