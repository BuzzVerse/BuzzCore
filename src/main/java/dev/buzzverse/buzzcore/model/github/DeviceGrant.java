package dev.buzzverse.buzzcore.model.github;

import jakarta.annotation.Nullable;
import org.springframework.security.core.Authentication;

import java.time.Instant;

public record DeviceGrant(
        String deviceCode,
        String userCode,
        Instant expiresAt,
        @Nullable Authentication authentication
) {}
