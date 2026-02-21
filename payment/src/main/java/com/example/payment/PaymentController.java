package com.example.payment;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.interfaces.ECPublicKey;
import java.util.Map;

@RestController
public class PaymentController {


    private ECPublicKey fetchPublicKeyFromKeycloak(String userId, String kid) {
        return null;
    }

    @GetMapping("/test")
    public Map<String, Object> testAuth() {
        return Map.of(
                "status", "Handcuff Verified!",
                "user_id", "jwt.getSubject()",
                "username", "sdafasdf",
                "message", "If you see this, Tyk and Keycloak successfully validated your DPoP session."
        );
    }

}
