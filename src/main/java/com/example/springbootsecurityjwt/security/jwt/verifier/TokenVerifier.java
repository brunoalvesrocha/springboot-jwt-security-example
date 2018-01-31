package com.example.springbootsecurityjwt.security.jwt.verifier;

public interface TokenVerifier {
    boolean verify(String jwt);
}
