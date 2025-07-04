package dev.buzzverse.buzzcore.chirpstack.service;

import dev.buzzverse.buzzcore.chirpstack.dto.*;
import dev.buzzverse.buzzcore.chirpstack.mapper.DeviceMapper;
import dev.buzzverse.buzzcore.client.ChirpStackClientManager;
import io.chirpstack.api.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class DeviceApiService implements DeviceApi {

    private final ChirpStackClientManager client;
    private final DeviceMapper mapper;

    @Override
    public List<DeviceSummaryDto> listDevices() {
        ListDevicesResponse resp = client.deviceStub().list(
                ListDevicesRequest.newBuilder()
                        .setApplicationId(client.applicationId())
                        .setLimit(1000)
                        .build());

        return resp.getResultList().stream().map(mapper::toSummary).toList();
    }

    @Override
    public DeviceDetailsDto getDevice(String devEui) {
        Device device = client.deviceStub().get(
                        GetDeviceRequest.newBuilder()
                                .setDevEui(devEui)
                                .build()).getDevice();

        DeviceActivation activation = client.deviceStub().getActivation(
                        GetDeviceActivationRequest.newBuilder()
                                .setDevEui(devEui)
                                .build()).getDeviceActivation();

        return mapper.toDetails(device, activation);
    }

    @Override
    public void addDevice(NewDeviceDto dto) {

        String profileId = pickProfile(dto.region(), dto.joinMode());

        Device device = Device.newBuilder()
                .setDevEui(dto.devEui())
                .setName(dto.name())
                .setApplicationId(client.applicationId())
                .setDeviceProfileId(profileId)
                .build();

        client.deviceStub().create(
                CreateDeviceRequest.newBuilder().setDevice(device).build());

        if (dto.joinMode() == LoraWanJoinMode.OTAA) {
            DeviceKeys keys = DeviceKeys.newBuilder()
                    .setDevEui(dto.devEui())
                    .setAppKey(dto.appKey())
                    .build();
            client.deviceStub().createKeys(
                    CreateDeviceKeysRequest.newBuilder().setDeviceKeys(keys).build());
        } else {
            DeviceActivation act = DeviceActivation.newBuilder()
                    .setDevEui(dto.devEui())
                    .setDevAddr(dto.devAddr())
                    .setAppSKey(dto.appSKey())
                    .setNwkSEncKey(dto.nwkSKey())
                    .build();
            ActivateDeviceRequest req = ActivateDeviceRequest.newBuilder()
                    .setDeviceActivation(act)
                    .build();
            client.deviceStub().activate(req);
        }
    }

    private String pickProfile(LoraMacRegion region, LoraWanJoinMode mode) {

        ListDeviceProfilesResponse resp = client.deviceProfileStub().list(
                ListDeviceProfilesRequest.newBuilder()
                        .setTenantId(client.tenantId())
                        .setLimit(100)
                        .build());

        for (DeviceProfileListItem item : resp.getResultList()) {
            boolean regionMatch = switch (region) {
                case EU433 -> item.getRegion() == Region.EU433;
                case EU868 -> item.getRegion() == Region.EU868;
            };
            boolean otaaOk = (mode == LoraWanJoinMode.OTAA) == item.getSupportsOtaa();

            if (regionMatch && otaaOk) return item.getId();
        }

        throw new IllegalStateException(
                "No device-profile for region %s + %s".formatted(region, mode));
    }

}
