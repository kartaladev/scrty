// record.ts records proof-vector.json from dpop.ts, the README's DPoP sample
// copied verbatim, under a WebCrypto runtime. Node.js 23.6 or later runs it as
// it is: node record.ts > proof-vector.json
//
// It records a sign-in's proof, and the RFC 7638 thumbprint of its key
// computed here, so the Go test checks the server's thumbprint against an
// independent one.

import { createDPoPKey, dpopProof } from "./dpop.ts";

const url = "http://example.com/login";
const keys = await createDPoPKey();
const proof = await dpopProof(keys, "post", url);

const { crv, kty, x, y } = await crypto.subtle.exportKey("jwk", keys.publicKey);
const canonical = JSON.stringify({ crv, kty, x, y });
const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)));
let binary = "";
for (const b of digest) binary += String.fromCharCode(b);
const jkt = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const iat = JSON.parse(atob(proof.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).iat;

console.log(JSON.stringify({
  recorded_with: `dpop.ts under Node.js ${process.version} WebCrypto`,
  method: "POST",
  url,
  iat,
  jkt,
  proof,
}, null, 2));
