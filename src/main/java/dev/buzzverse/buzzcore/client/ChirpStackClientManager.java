package dev.buzzverse.buzzcore.client;

import dev.buzzverse.buzzcore.config.ChirpStackProperties;
import io.chirpstack.api.*;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.MetadataUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class ChirpStackClientManager {

    private final ChirpStackProperties props;

    private ManagedChannel channel;
    private ClientInterceptor authInterceptor;

    @PostConstruct
    private void init() {
        log.info("Connecting to ChirpStack gRPC @ {}", props.getGrpc().getServer());

        channel = NettyChannelBuilder
                .forTarget(props.getGrpc().getServer())
                .useTransportSecurity()
                .keepAliveTime(30, TimeUnit.SECONDS)
                .keepAliveTimeout(10, TimeUnit.SECONDS)
                .keepAliveWithoutCalls(true)
                .build();

        Metadata md = new Metadata();
        Metadata.Key<String> AUTH = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
        md.put(AUTH, "Bearer " + props.getGrpc().getApiKey());

        authInterceptor = MetadataUtils.newAttachHeadersInterceptor(md);
    }

    @PreDestroy
    private void shutdown() throws InterruptedException {
        if (channel != null) {
            log.info("Shutting down ChirpStack gRPC channel…");
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    public TenantServiceGrpc.TenantServiceBlockingStub tenantStub() {
        return TenantServiceGrpc.newBlockingStub(channel).withInterceptors(authInterceptor);
    }

    public ApplicationServiceGrpc.ApplicationServiceBlockingStub applicationStub() {
        return ApplicationServiceGrpc.newBlockingStub(channel).withInterceptors(authInterceptor);
    }

    public DeviceServiceGrpc.DeviceServiceBlockingStub deviceStub() {
        return DeviceServiceGrpc.newBlockingStub(channel).withInterceptors(authInterceptor);
    }

    public InternalServiceGrpc.InternalServiceStub internalStub() {
        return InternalServiceGrpc.newStub(channel).withInterceptors(authInterceptor);
    }

    public DeviceProfileServiceGrpc.DeviceProfileServiceBlockingStub deviceProfileStub() {
        return DeviceProfileServiceGrpc.newBlockingStub(channel).withInterceptors(authInterceptor);
    }

    public String tenantId() {
        return props.getTenantId();
    }

    public String applicationId() {
        return props.getApplicationId();
    }

}
