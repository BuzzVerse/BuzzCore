package dev.buzzverse.buzzcore.controller;

import dev.buzzverse.buzzcore.model.github.DeviceGrant;
import dev.buzzverse.buzzcore.service.DeviceGrantStore;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/cli/auth")
@RequiredArgsConstructor
public class CliAuthController {

    private final DeviceGrantStore store;
    private final JwtEncoder jwtEncoder;

    @PostMapping("/request")
    public Map<String,Object> request() {
        DeviceGrant g = store.create();
        return Map.of(
                "device_code",      g.deviceCode(),
                "user_code",        g.userCode(),
                "verification_uri", "/cli/verify"
        );
    }

    @GetMapping("/poll")
    public ResponseEntity<?> poll(@RequestParam String deviceCode) {
        DeviceGrant g = store.byDevice(deviceCode).orElse(null);

        if (g == null || g.expiresAt().isBefore(Instant.now())) {
            return ResponseEntity.status(410).body(Map.of("error","expired_device_code"));
        }

        if (g.authentication() == null) {
            return ResponseEntity.status(428).body(Map.of("error","authorization_pending"));
        }

        Authentication auth = g.authentication();
        List<String> roles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("buzzcore-cli")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(900))
                .subject(auth.getName())
                .claim("roles", roles)
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = jwtEncoder
                .encode(JwtEncoderParameters.from(header, claims))
                .getTokenValue();

        return ResponseEntity.ok(Map.of(
                "access_token", token,
                "expires_in", 900
        ));
    }

}
