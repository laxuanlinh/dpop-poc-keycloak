Step 1: Run npm install jose

Step 2: docker compose up

Step 3: Go to localhost:8080, login to Keycloak with admin/admin and create a new realm poc-linh

Step 4: Create a client poc-linh-app with standard flow and direct access grant flow (for testing)

Step 5: Enable DPoP for the new client

Step 6: Configure the WebAuthN Passwordless policy and add the WebAuthN Passwordless Authenticator as a Required execution

Step 7: Run node generate_dpop.mjs with the keycloak URL to generate the DPoP token

Step 8: Call the http://localhost:8080/realms/poc-linh/protocol/openid-connect/token endpoint with username/password and the DPoP token to get the access token 

Step 9: Run node generate_dpop.mjs again but this time with the Tyk endpoint to generate the DPoP token for Tyk and the payment service behind it

Step 10: Use both DPoP token and the access token to access token to access the endpoint
