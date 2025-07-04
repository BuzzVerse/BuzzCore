package dev.buzzverse.buzzcore.service;

import dev.buzzverse.buzzcore.config.JwtProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtProperties props;

    public String generateToken(Authentication auth) {
        Instant now = Instant.now();

        List<String> roles = auth.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(props.getIssuer())
                .subject(auth.getName())
                .issuedAt(now)
                .expiresAt(now.plus(props.getTtl()))
                .claim("roles", roles);

        if (auth instanceof OAuth2AuthenticationToken oauth) {
            Map<String, Object> attrs = oauth.getPrincipal().getAttributes();
            claims.claim("login", attrs.get("login"));
            claims.claim("name", attrs.get("name"));
            claims.claim("email", attrs.get("email"));
            claims.claim("provider", oauth.getAuthorizedClientRegistrationId());
        }

        JwsHeader jwsHeader = JwsHeader.with(props.getAlg()).build();

        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims.build()))
                .getTokenValue();
    }

    public long getTtlSeconds() {
        return props.getTtl().toSeconds();
    }

}

