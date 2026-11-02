// dpop.ts
const encoder = new TextEncoder();

function base64url(bytes: ArrayBuffer | Uint8Array): string {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function createDPoPKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
}

export interface ProofOptions {
  accessToken?: string; // the token sent as "Authorization: DPoP"; none at sign-in
  nonce?: string;       // the last DPoP-Nonce the server sent
}

export async function dpopProof(
  keys: CryptoKeyPair,
  method: string,
  url: string,
  options: ProofOptions = {},
): Promise<string> {
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const target = new URL(url, globalThis.location?.href);

  const header = { typ: "dpop+jwt", alg: "ES256", jwk: { kty, crv, x, y } };
  const claims: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: method.toUpperCase(),
    htu: target.origin + target.pathname,
    iat: Math.floor(Date.now() / 1000),
  };
  if (options.accessToken) {
    claims.ath = base64url(await crypto.subtle.digest("SHA-256", encoder.encode(options.accessToken)));
  }
  if (options.nonce) {
    claims.nonce = options.nonce;
  }

  const input = `${base64url(encoder.encode(JSON.stringify(header)))}.${base64url(encoder.encode(JSON.stringify(claims)))}`;
  // WebCrypto's ECDSA signature is r || s, the encoding JWS uses for ES256.
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, encoder.encode(input));

  return `${input}.${base64url(signature)}`;
}
