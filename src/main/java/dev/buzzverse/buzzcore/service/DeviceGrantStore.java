package dev.buzzverse.buzzcore.service;

import dev.buzzverse.buzzcore.model.github.DeviceGrant;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class DeviceGrantStore {
    private final Map<String, DeviceGrant> byDevice = new ConcurrentHashMap<>();
    private final Map<String, DeviceGrant> byUser = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public DeviceGrant create() {
        String device = UUID.randomUUID().toString();
        String user = String.format("%04d-%04d", random.nextInt(10_000), random.nextInt(10_000));
        DeviceGrant deviceGrant = new DeviceGrant(device, user, Instant.now().plusSeconds(600), null);
        byDevice.put(device, deviceGrant);
        byUser.put(user, deviceGrant);
        return deviceGrant;
    }

    public Optional<DeviceGrant> byDevice(String device) {
        return Optional.ofNullable(byDevice.get(device));
    }

    public Optional<DeviceGrant> byUser(String user) {
        return Optional.ofNullable(byUser.get(user));
    }

    public void complete(String device, Authentication auth) {
        byDevice.compute(device, (k, g) -> new DeviceGrant(g.deviceCode(), g.userCode(), g.expiresAt(), auth));
    }

}
