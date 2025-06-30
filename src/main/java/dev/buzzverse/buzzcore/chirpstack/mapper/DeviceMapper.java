package dev.buzzverse.buzzcore.chirpstack.mapper;

import dev.buzzverse.buzzcore.chirpstack.dto.DeviceDetailsDto;
import dev.buzzverse.buzzcore.chirpstack.dto.DeviceSummaryDto;
import dev.buzzverse.buzzcore.chirpstack.dto.NewDeviceDto;
import io.chirpstack.api.Device;
import io.chirpstack.api.DeviceActivation;
import io.chirpstack.api.DeviceListItem;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface DeviceMapper {

    DeviceSummaryDto toSummary(DeviceListItem src);

    @Mapping(target = "devEui", source = "device.devEui")
    @Mapping(target = "devAddr", source = "activation.devAddr")
    @Mapping(target = "appSKey", source = "activation.appSKey")
    @Mapping(target = "nwkSEncKey", source = "activation.nwkSEncKey")
    DeviceDetailsDto toDetails(Device device, DeviceActivation activation);

    Device toProto(NewDeviceDto dto);

}
