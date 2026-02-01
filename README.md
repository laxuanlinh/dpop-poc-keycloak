Step 1: Run npm install jose

Step 2: docker compose up

Step 3: Go to localhost:8080, login to Keycloak with admin/admin and create a new realm poc-linh

Step 4: Create a client poc-linh-app with standard flow and direct access grant flow (for testing)

Step 5: Enable DPoP for the new client

Step 6: Configure the WebAuthN Passwordless policy and add the WebAuthN Passwordless Authenticator as a Required execution

Step 7: Run node generate_dpop.mjs 

Expected result: The script first generate a keypair, use them to generate a DPoP proof with keycloak domain and successfully fetches an access token from Keycloak, then it generate a DPoP proof for payment service/Tyk and use both DPoP and access token to access the endpoint

*Still unsuccessul so far*
