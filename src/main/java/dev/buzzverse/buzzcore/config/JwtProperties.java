package dev.buzzverse.buzzcore.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;

import java.time.Duration;

@Configuration
@Getter @Setter
@ConfigurationProperties(prefix = "buzzcore.jwt")
public class JwtProperties {
    private String issuer = "buzzcore-cli";
    private Duration ttl = Duration.ofMinutes(15);
    private MacAlgorithm alg = MacAlgorithm.HS256;
}