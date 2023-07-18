package tien.baseproject.gatewayservice.service.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tien.baseproject.gatewayservice.dto.BaseResponse;
import tien.baseproject.gatewayservice.service.JwtService;

import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtServiceImpl implements JwtService {
    private long lastKeyFetchingTime = 0L;

    @Value("${jwt.time-refresh-key}")

    private long timePublicKeyRefreshRateLimit;
    private static final String BEARER_PREFIX = "Bearer ";
    private RSAPublicKey rsaPublicKey;
    private final WebClient.Builder webClientBuilder;
    @Value("${jwt.url-fetching-key}")
    private String urlFetchingKey;

    @SneakyThrows
    @Override
    public Mono<Boolean> verifyToken(String token) {

        if (token.trim().isEmpty() || !token.startsWith(BEARER_PREFIX)) {
            return Mono.just(Boolean.FALSE);
        }
        token = token.replace("Bearer ", "");
        JWSObject jwsObject = JWSObject.parse(token);
        return getPublicKey()
                .map(publicKey -> {
                    RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
                    try {
                        return jwsObject.verify(verifier);
                    } catch (JOSEException e) {
                        lastKeyFetchingTime = 0L;
                        log.error("Exception when verify token: ", e);
                        return Boolean.FALSE;
                    }
                });
    }

    private Mono<RSAPublicKey> getPublicKey() {
        long t = System.currentTimeMillis();
        if (lastKeyFetchingTime == 0L || t - lastKeyFetchingTime >= timePublicKeyRefreshRateLimit) {
            return fetchingKey()
                    .map(publicKey -> {
                        try {
                            byte[] encoded = Base64.decodeBase64(publicKey);
                            KeyFactory kf = KeyFactory.getInstance("RSA");
                            return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
                        } catch (Exception e) {
                            log.error("Exception when get public key: ", e);
                        }
                        return (RSAPublicKey) rsaPublicKey;
                    });
        }
        return Mono.just(rsaPublicKey);
    }

    private Mono<String> fetchingKey() {
        return webClientBuilder
                .build()
                .get()
                .uri(urlFetchingKey)
                .retrieve()
                .bodyToMono(BaseResponse.class)
                .map(BaseResponse::getData);


    }

}
