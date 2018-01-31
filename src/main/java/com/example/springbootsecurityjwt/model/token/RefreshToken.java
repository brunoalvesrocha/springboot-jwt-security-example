package com.example.springbootsecurityjwt.model.token;

import com.example.springbootsecurityjwt.security.model.Scopes;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import java.util.List;
import java.util.Optional;

public class RefreshToken implements JwtToken {

    private Jws<Claims> claims;

    public RefreshToken(Jws<Claims> claims) {
        this.claims = claims;
    }

    public static Optional<RefreshToken> create(RawAccessJwtToken token, String signinKey) {
        Jws<Claims> claims = token.parseClaims(signinKey);

        List<String> scopes = claims.getBody().get("scopes", List.class);
        if(scopes == null || scopes.isEmpty()
                || !scopes.stream()
                .filter(scope ->
                        Scopes.REFRESH_TOKEN.authority().equals(scope))
                .findFirst().isPresent()) {
            return Optional.empty();
        }

        return Optional.of(new RefreshToken(claims));
    }

    @Override
    public String getToken() {
        return null;
    }

    public Jws<Claims> getClaims() {
        return claims;
    }

    public String getJti() {
        return claims.getBody().getId();
    }

    public String getSubject() {
        return claims.getBody().getSubject();
    }
}
