package dev.buzzverse.buzzcore.service;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import dev.buzzverse.buzzcore.BuzzVerse_V1_BME280.BME280Data;
import dev.buzzverse.buzzcore.BuzzVerse_V1_Packet.Packet;
import dev.buzzverse.buzzcore.client.InfluxDBClientManager;
import dev.buzzverse.buzzcore.model.BME280Measurement;
import dev.buzzverse.buzzcore.model.BatteryMeasurement;
import dev.buzzverse.buzzcore.model.ChirpStackEvent;
import io.chirpstack.api.gw.UplinkRxInfo;
import io.chirpstack.api.integration.StatusEvent;
import io.chirpstack.api.integration.UplinkEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@Service
@RequiredArgsConstructor
public class ChirpStackEventService {

    private final InfluxDBClientManager influxManager;

    public void handleEvent(final ChirpStackEvent event, final byte[] requestBody) {
        try {
            switch (event) {
                case UP -> handleUplinkEvent(requestBody);
                case STATUS -> handleStatusEvent(requestBody);
                default -> {
                    log.error("Unknown event type: {}", event);
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown event type");
                }
            }
        } catch (final InvalidProtocolBufferException e) {
            log.error("Error parsing protobuf data", e);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Error parsing protobuf data", e);
        } catch (final Exception e) {
            log.error("Error while handling event", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error while handling event", e);
        }
    }

    private void handleUplinkEvent(final byte[] requestBody) throws InvalidProtocolBufferException {
        final UplinkEvent uplinkEvent = UplinkEvent.parseFrom(requestBody);
        final String devEui = uplinkEvent.getDeviceInfo().getDevEui();
        log.info("Received uplink event from device: {}", devEui);

        final ByteString payload = uplinkEvent.getData();
        final Packet packet = Packet.parseFrom(payload);

        if (uplinkEvent.getRxInfoList().isEmpty()) {
            log.warn("No RxInfo available for device: {}", devEui);
            return;
        }

        final UplinkRxInfo uplinkRxInfo = uplinkEvent.getRxInfoList().get(0);

        if (packet.hasBme280()) {
            final BME280Data bme280Data = packet.getBme280();
            final int pressure = bme280Data.getPressure() + 1000;
            final BME280Measurement measurement = BME280Measurement.builder()
                    .deviceEui(devEui)
                    .rssi(uplinkRxInfo.getRssi())
                    .snr(uplinkRxInfo.getSnr())
                    .temperature(bme280Data.getTemperature())
                    .humidity(bme280Data.getHumidity())
                    .pressure(pressure)
                    .build();

            log.info("Saving BME280 measurement: {}", measurement);
            influxManager.writeMeasurement(measurement);
        }
    }

    private void handleStatusEvent(final byte[] requestBody) throws InvalidProtocolBufferException {
        final StatusEvent statusEvent = StatusEvent.parseFrom(requestBody);
        final String devEui = statusEvent.getDeviceInfo().getDevEui();
        log.info("Received status event from device: {}", devEui);

        final boolean isExternalPower = statusEvent.getExternalPowerSource();
        final float batteryLevel = statusEvent.getBatteryLevel();

        final BatteryMeasurement measurement = BatteryMeasurement.builder()
                .deviceEui(devEui)
                .isExternalPower(isExternalPower)
                .batteryLevel(batteryLevel)
                .build();

        log.info("Saving battery measurement: {}", measurement);
        influxManager.writeMeasurement(measurement);
    }
}