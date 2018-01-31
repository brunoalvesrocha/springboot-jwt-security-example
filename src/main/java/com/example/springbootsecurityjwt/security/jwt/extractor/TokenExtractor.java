package com.example.springbootsecurityjwt.security.jwt.extractor;

public interface TokenExtractor {
    String extract(String payload);
}
