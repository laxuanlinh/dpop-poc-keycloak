import * as jose from 'jose';
import fs from 'fs';

// --- CONFIGURATION ---
const KEY_FILE = './keys.json';
const REALM_URL = 'http://localhost:8080/realms/poc-linh';
const TOKEN_URL = `${REALM_URL}/protocol/openid-connect/token`;
const PAYMENT_URL = 'http://localhost:8081/payment/test';

const CLIENT_ID = 'poc-linh-app';
const USERNAME = 'test'; // Your test user
const PASSWORD = '123';

async function run() {
  // 1. Load Keys
  if (!fs.existsSync(KEY_FILE)) throw new Error("Please run your key generation script first!");
  const { privateKeyJWK, publicKeyJWK } = JSON.parse(fs.readFileSync(KEY_FILE, 'utf-8'));
  const privateKey = await jose.importJWK(privateKeyJWK, 'ES256');
  console.log("Private key:", privateKeyJWK);
  console.log("Public key:", publicKeyJWK);

  // 2. Generate DPoP Proof
  const dpopProof = await new jose.SignJWT({
    htu: "http://localhost:8080/realms/poc-linh/protocol/openid-connect/token",
    htm: "POST",
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000)
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "dpop+jwt",
      jwk: publicKeyJWK
    })
    .sign(privateKey);

  console.log("DPoP Proof:", dpopProof);

  // 3. Request Access Token with DPoP
  const tokenResponse = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'DPoP': dpopProof
    },
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: CLIENT_ID,
      username: USERNAME,
      password: PASSWORD,
      scope: 'openid'
    })
  });

  if (!tokenResponse.ok) {
    const errorText = await tokenResponse.text();
    throw new Error(`Token request failed: ${errorText}`);
  }

  const tokenData = await tokenResponse.json();
  console.log("Access Token Response:", tokenData);

  const dpopProof2 = await new jose.SignJWT({
    htu: "http://localhost:8081/payment/test",
    htm: "GET",
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000)
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "dpop+jwt",
      jwk: publicKeyJWK
    })
    .sign(privateKey);

  console.log("DPoP Proof:", dpopProof2);


}

run().catch(console.error);
