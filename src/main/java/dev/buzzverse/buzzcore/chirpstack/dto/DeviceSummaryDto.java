package dev.buzzverse.buzzcore.chirpstack.dto;

public record DeviceSummaryDto(
        String deviceProfileName,
        String devEui,
        String name
) {}
