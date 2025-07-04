package dev.buzzverse.buzzcore.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "chirpstack")
public class ChirpStackProperties {
    private String tenantId;
    private String applicationId;
    private final Grpc grpc = new Grpc();

    @Data
    public static class Grpc {
        private String server;
        private String apiKey;
    }

}
