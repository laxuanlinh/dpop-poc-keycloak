import * as jose from 'jose';
import fs from 'fs';

async function setup() {
  // Generate the key pair
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256', {
    extractable: true // Required to allow exportJWK
  });

  // Export keys to JSON format (JWK)
  const keys = {
    privateKeyJWK: await jose.exportJWK(privateKey),
    publicKeyJWK: await jose.exportJWK(publicKey)
  };

  // Save to a file named 'keys.json'
  fs.writeFileSync('./keys.json', JSON.stringify(keys, null, 2));
  console.log("Keys saved to keys.json successfully.");
}

setup();
