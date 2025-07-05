package dev.buzzverse.buzzcore.client;

import dev.buzzverse.buzzcore.config.ChirpStackProperties;
import io.chirpstack.api.DeviceProfileServiceGrpc;
import io.chirpstack.api.DeviceServiceGrpc;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.MetadataUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class ChirpStackClientManager {

    private final ChirpStackProperties props;
    private final ManagedChannel channel;
    private final ClientInterceptor authInterceptor;

    public ChirpStackClientManager(ChirpStackProperties props) {
        this.props = props;
        this.channel = NettyChannelBuilder.forTarget(props.getGrpc().getServer())
                .useTransportSecurity()
                .keepAliveTime(30, TimeUnit.SECONDS)
                .keepAliveTimeout(10, TimeUnit.SECONDS)
                .keepAliveWithoutCalls(true)
                .build();

        Metadata md = new Metadata();
        Metadata.Key<String> AUTH = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
        md.put(AUTH, "Bearer " + props.getGrpc().getApiKey());

        this.authInterceptor = MetadataUtils.newAttachHeadersInterceptor(md);
    }

    public DeviceServiceGrpc.DeviceServiceBlockingStub deviceStub() {
        return DeviceServiceGrpc.newBlockingStub(channel).withInterceptors(authInterceptor);
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

    @PreDestroy
    public void shutdown() throws InterruptedException {
        log.info("Shutting down ChirpStack gRPC channel…");
        channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }

}
