package com.example.springbootsecurityjwt.security.jwt.verifier;

import org.springframework.stereotype.Component;

@Component
public class BloomFilterTokenVerifier implements TokenVerifier {
    @Override
    public boolean verify(String jwt) {
        return true;
    }
}
