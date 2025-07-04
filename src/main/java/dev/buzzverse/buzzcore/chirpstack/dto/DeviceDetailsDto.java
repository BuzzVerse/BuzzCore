package dev.buzzverse.buzzcore.chirpstack.dto;


public record DeviceDetailsDto(
        String devEui,
        String devAddr,
        String appSKey,
        String nwkSEncKey,
        String name,
        String applicationId,
        String deviceProfileId
) {}
