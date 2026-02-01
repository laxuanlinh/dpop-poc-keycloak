// Sample using 'jose' library in Node.js/Browser
import * as jose from 'jose';

async function generateDPoP(method, url, accessToken, privateKey, publicKeyJWK) {
  const dpop = await new jose.SignJWT({
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    ath: accessToken ? await computeAth(accessToken) : undefined
  })
    .setProtectedHeader({
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: publicKeyJWK, // Public key goes in the header
    })
    .sign(privateKey); // Sign with the private key
  console.log("Generated DPoP Token:", dpop);
  return dpop;
}

// Function to compute the 'ath' claim (SHA-256 hash of the token)
async function computeAth(token) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const { privateKey, publicKey } = await jose.generateKeyPair('ES256');

// 2. Convert the public key to JWK format (this goes into the JWT header)
const publicKeyJWK = await jose.exportJWK(publicKey);
const dpopProof = await generateDPoP(
  'POST', 
  // 'http://localhost:8080/realms/poc-linh/protocol/openid-connect/token',
  'http://localhost:8081/payments', 
  null, // Use null if you're getting the token for the first time
  privateKey, 
  publicKeyJWK
);

console.log("Your DPoP Header Value:");
console.log(dpopProof);
