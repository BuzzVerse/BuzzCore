package dev.buzzverse.buzzcore.model.dto;

public record TokenResponse(
        String accessToken,
        long expiresIn
) {}
