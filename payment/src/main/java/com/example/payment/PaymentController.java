package com.example.payment;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.interfaces.ECPublicKey;
import java.util.Map;

@RestController
public class PaymentController {

    @PostMapping
    public String handlePayment(@RequestHeader("X-Transaction-Signature") String jws,
                                @AuthenticationPrincipal Jwt jwt) throws Exception {
        String userId = jwt.getSubject(); // Extracted from Keycloak token
        
        // 1. Parse the JWS (The signed request body)
        JWSObject jwsObject = JWSObject.parse(jws);
        String kid = jwsObject.getHeader().getKeyID();

        // 2. Fetch Public Key from Keycloak Admin API
        // For the POC, you can mock this or call the Admin API
        ECPublicKey publicKey = fetchPublicKeyFromKeycloak(userId, kid);

        // 3. Verify the signature
        JWSVerifier verifier = new ECDSAVerifier(publicKey);
        if (jwsObject.verify(verifier)) {
            return "✅ Payment authorized by hardware signature!";
        } else {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Signature Invalid");
        }
    }

    private ECPublicKey fetchPublicKeyFromKeycloak(String userId, String kid) {
        return null;
    }

    @GetMapping("/test")
    public Map<String, Object> testAuth(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "status", "Handcuff Verified!",
                "user_id", jwt.getSubject(),
                "username", jwt.getClaimAsString("preferred_username"),
                "message", "If you see this, Tyk and Keycloak successfully validated your DPoP session."
        );
    }

}
