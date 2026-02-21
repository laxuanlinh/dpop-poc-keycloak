## Step 1: Run docker compose up
It should starts up Redis, Keycloak, Tyk DPoP plugin and Tyk Gateway

## Step 2: Run node generate_dpop.mjs
This generates a keypair (in real scenarios, devices handle this so we will never see the keypair, this is solely for demonstration). Then it uses the private key to sign a request object which includes the token URL, public key... and uses this signed DPoP proof to call the token URL. Keycloak returns an access token that tied to the DPoP proof. 
The script creates a 2nd DPoP proof with the URL of the resource server which can be used to sendto the Tyk endpoint along with the access token.

## Step 3: Copy the access token and the 2nd DPoP proof to call the Tyk endpoint with headers:
- Authorization: DPoP (access token)
- DPoP: (the 2nd DPoP proof)

## Step 4: Watch the logs to see the plugin is triggered to validate DPoP proof first, then conver the DPoP prefix to Bearer to the built-in authentication plugin of Tyk. Tyk then authenticates using the JWK endpoint of keycloak