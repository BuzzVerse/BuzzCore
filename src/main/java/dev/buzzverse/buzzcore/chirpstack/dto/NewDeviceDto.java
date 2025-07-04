package dev.buzzverse.buzzcore.chirpstack.dto;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.*;

public record NewDeviceDto(

        @NotNull
        @Pattern(regexp = "^[0-9A-Fa-f]{16}$")
        String devEui,

        @NotBlank @Size(max = 100)
        String name,

        @NotNull
        LoraMacRegion region,

        @NotNull
        LoraWanJoinMode joinMode,

        @Nullable
        @Pattern(regexp = "^[0-9A-Fa-f]{16}$")
        String joinEui,

        @Nullable
        @Pattern(regexp = "^[0-9A-Fa-f]{32}$")
        String appKey,

        @Nullable
        @Pattern(regexp = "^[0-9A-Fa-f]{8}$")
        String devAddr,

        @Nullable
        @Pattern(regexp = "^[0-9A-Fa-f]{32}$")
        String appSKey,

        @Nullable
        @Pattern(regexp = "^[0-9A-Fa-f]{32}$")
        String nwkSKey
) {

    @AssertTrue(message = "OTAA: appKey missing or ABP keys present")
    private boolean otaaValid() {
        if (joinMode == LoraWanJoinMode.OTAA) {
            return appKey != null && devAddr == null && appSKey == null && nwkSKey == null;
        }
        return true;
    }

    @AssertTrue(message = "ABP: devAddr/appSKey/nwkSKey missing or OTAA keys present")
    private boolean abpValid() {
        if (joinMode == LoraWanJoinMode.ABP) {
            return devAddr != null && appSKey != null && nwkSKey != null && appKey == null;
        }
        return true;
    }

}
