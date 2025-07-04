package dev.buzzverse.buzzcore.controller;

import dev.buzzverse.buzzcore.model.dto.DeviceGrantResponse;
import dev.buzzverse.buzzcore.model.dto.TokenResponse;
import dev.buzzverse.buzzcore.model.github.DeviceGrant;
import dev.buzzverse.buzzcore.service.DeviceGrantStore;
import dev.buzzverse.buzzcore.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;

@RestController
@RequestMapping("/cli/auth")
@RequiredArgsConstructor
public class CliAuthController {

    private final DeviceGrantStore store;
    private final JwtService jwtService;

    @PostMapping("/request")
    public DeviceGrantResponse request() {
        DeviceGrant grant = store.create();
        return new DeviceGrantResponse(grant.deviceCode(), grant.userCode(), "/cli/verify");
    }

    @GetMapping("/poll")
    public TokenResponse poll(@RequestParam String deviceCode) {
        DeviceGrant grant = store.byDevice(deviceCode)
                .filter(d -> !d.expiresAt().isBefore(Instant.now()))
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.GONE, "expired_device_code"));

        if (grant.authentication() == null) {
            throw new ResponseStatusException(
                    HttpStatus.PRECONDITION_REQUIRED, "authorization_pending");
        }

        return new TokenResponse(
                jwtService.generateToken(grant.authentication()),
                jwtService.getTtlSeconds()
        );
    }

}
