package dev.buzzverse.buzzcore.controller;

import dev.buzzverse.buzzcore.chirpstack.dto.DeviceDetailsDto;
import dev.buzzverse.buzzcore.chirpstack.dto.DeviceSummaryDto;
import dev.buzzverse.buzzcore.chirpstack.dto.NewDeviceDto;
import dev.buzzverse.buzzcore.chirpstack.service.DeviceApi;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/devices")
public class DeviceController {

    private final DeviceApi service;

    @GetMapping
    public List<DeviceSummaryDto> list() {
        return service.listDevices();
    }

    @GetMapping("/{devEui}")
    public DeviceDetailsDto details(@PathVariable String devEui) {
        return service.getDevice(devEui);
    }

    @PostMapping
    public ResponseEntity<Void> add(@Valid @RequestBody NewDeviceDto dto) {
        service.addDevice(dto);
        return ResponseEntity.ok().build();
    }

}
