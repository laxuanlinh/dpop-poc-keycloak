import * as jose from 'jose';
import fs from 'fs';

// --- CONFIGURATION ---
const KEY_FILE = './keys.json';
const REALM_URL = 'http://localhost:8080/realms/poc-linh';
const TOKEN_URL = `${REALM_URL}/protocol/openid-connect/token`;
const PAYMENT_URL = 'http://localhost:8081/payment/test';

const CLIENT_ID = 'poc-linh-app';
const USERNAME = 'laxuanlinh'; // Your test user
const PASSWORD = '123'; 

async function computeAth(token) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generateDPoP(method, url, accessToken, privateKey, publicKeyJWK) {
  const payload = {
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  };
  if (accessToken) payload.ath = await computeAth(accessToken);

  return await new jose.SignJWT(payload)
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicKeyJWK })
    .sign(privateKey);
}

async function run() {
  // 1. Load Keys
  if (!fs.existsSync(KEY_FILE)) throw new Error("Please run your key generation script first!");
  const { privateKeyJWK, publicKeyJWK } = JSON.parse(fs.readFileSync(KEY_FILE, 'utf-8'));
  const privateKey = await jose.importJWK(privateKeyJWK, 'ES256');

  // --- STEP 1: GET THE ACCESS TOKEN ---
  console.log("1️⃣ Requesting DPoP-bound Access Token from Keycloak...");
  const tokenDPoP = await generateDPoP('POST', TOKEN_URL, null, privateKey, publicKeyJWK);

  const params = new URLSearchParams({
    grant_type: 'password',
    client_id: CLIENT_ID,
    username: USERNAME,
    password: PASSWORD,
    scope: 'openid profile email'
  });

  const tokenResponse = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 
        'Content-Type': 'application/x-www-form-urlencoded',
        'DPoP': tokenDPoP 
    },
    body: params
  });

  const tokenData = await tokenResponse.json();
  if (!tokenResponse.ok) {
    console.error("❌ Keycloak Error:", tokenData);
    return;
  }

  const accessToken = tokenData.access_token;
  console.log("\n✅ ACCESS TOKEN RECEIVED:");
  console.log("------------------------------------------------------------");
  console.log(accessToken);
  console.log("------------------------------------------------------------");

  // --- STEP 2: CALL PAYMENT SERVICE ---
  console.log("\n2️⃣ Generating DPoP Proof for Payment Service...");
  const paymentDPoP = await generateDPoP('POST', PAYMENT_URL, accessToken, privateKey, publicKeyJWK);

  console.log("\n🚀 FINAL HEADERS FOR POSTMAN / CURL:");
  console.log(`Authorization: DPoP ${accessToken}`);
  console.log(`DPoP: ${paymentDPoP}`);

  
  // OPTIONAL: Uncomment to actually fire the request to your payment service
  const paymentResponse = await fetch(PAYMENT_URL, {
    method: 'POST',
    headers: {
      'Authorization': `DPoP ${accessToken}`,
      'DPoP': paymentDPoP
    }
  });
  console.log("\nPayment Service Status:", paymentResponse.status);
  
}

run().catch(console.error);
