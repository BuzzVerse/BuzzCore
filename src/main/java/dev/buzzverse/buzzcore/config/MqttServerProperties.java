package dev.buzzverse.buzzcore.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "mqtt")
public class MqttServerProperties {
    private String serverUri;
    private String clientId;
    private String username;
    private String password;
}
