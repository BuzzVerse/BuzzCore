package dev.buzzverse.buzzcore.chirpstack.service;

import dev.buzzverse.buzzcore.chirpstack.dto.DeviceDetailsDto;
import dev.buzzverse.buzzcore.chirpstack.dto.DeviceSummaryDto;
import dev.buzzverse.buzzcore.chirpstack.dto.NewDeviceDto;

import java.util.List;

public interface DeviceApi {
    List<DeviceSummaryDto> listDevices();

    DeviceDetailsDto getDevice(String devEui);

    void addDevice(NewDeviceDto newDevice);
}
