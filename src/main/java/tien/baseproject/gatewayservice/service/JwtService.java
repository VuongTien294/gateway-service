package tien.baseproject.gatewayservice.service;

import lombok.SneakyThrows;
import reactor.core.publisher.Mono;

public interface JwtService {
    @SneakyThrows
    Mono<Boolean> verifyToken(String token);
}
