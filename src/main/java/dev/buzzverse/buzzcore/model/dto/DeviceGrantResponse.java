package dev.buzzverse.buzzcore.model.dto;

public record DeviceGrantResponse(
        String deviceCode,
        String userCode,
        String verificationUri
) {}
