import * as jose from 'jose';
import fs from 'fs';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';

// --- CONFIGURATION ---
const KEY_FILE = './keys.json';
const REALM_URL = 'http://localhost:8080/realms/poc-linh';
const TOKEN_URL = `${REALM_URL}/protocol/openid-connect/token`;
const PAYMENT_URL = 'http://localhost:8081/payment/test';

const CLIENT_ID = 'poc-linh-app';
const USERNAME = 'test';
const PASSWORD = '123';

const rl = readline.createInterface({ input, output });

async function step(message) {
  console.log(`\n=== ${message} ===`);
  await rl.question("Press ENTER to continue...");
}

async function run() {

  // 1. Load Keys
  await step("Step 1: Load client key pair (used for DPoP signing)");

  if (!fs.existsSync(KEY_FILE)) throw new Error("Please run your key generation script first!");
  const { privateKeyJWK, publicKeyJWK } = JSON.parse(fs.readFileSync(KEY_FILE, 'utf-8'));

  const privateKey = await jose.importJWK(privateKeyJWK, 'ES256');

  console.log("Private key:", privateKeyJWK);
  console.log("Public key:", publicKeyJWK);


  // 2. Generate DPoP Proof for /token
  await step("Step 2: Generate DPoP proof JWT for the /token endpoint");

  const dpopProof = await new jose.SignJWT({
    htu: TOKEN_URL,
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

  console.log("DPoP Proof for /token:\n", dpopProof);


  // 3. Request Access Token
  await step("Step 3: Call /token with the DPoP proof to obtain a DPoP-bound access token");

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


  // 4. Generate DPoP proof for API call
  await step("Step 4: Generate a NEW DPoP proof for the protected API request");

  const dpopProof2 = await new jose.SignJWT({
    htu: PAYMENT_URL,
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

  console.log("DPoP Proof for API call:\n", dpopProof2);


  // 5. Call protected API
  await step("Step 5: Call the protected API with the DPoP-bound access token");

  const apiResponse = await fetch(PAYMENT_URL, {
    method: 'GET',
    headers: {
      'Authorization': `DPoP ${tokenData.access_token}`,
      'DPoP': dpopProof2
    }
  });

  const apiData = await apiResponse.text();

  console.log("API Response:", apiData);

  await rl.close();
}

run().catch(console.error);