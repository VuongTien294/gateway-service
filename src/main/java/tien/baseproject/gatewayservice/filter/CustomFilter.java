package tien.baseproject.gatewayservice.filter;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import tien.baseproject.gatewayservice.properties.RoutingProperties;
import tien.baseproject.gatewayservice.service.JwtService;
import tien.baseproject.gatewayservice.util.JwtTokenUtils;
import tien.baseproject.gatewayservice.util.ServletUtils;


@Component
@RequiredArgsConstructor
@Slf4j
public class CustomFilter implements WebFilter {
    private final JwtService jwtService;
    private final RoutingProperties routingProperties;
    private final JwtTokenUtils jwtTokenUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange serverWebExchange, @NonNull WebFilterChain webFilterChain) {
        String requestUri = serverWebExchange.getRequest().getPath().toString();
        if (isInternalNotAllowed(requestUri)) {
            return completeUnauthorizedRequest(serverWebExchange);
        }

        HttpMethod requestMethod = serverWebExchange.getRequest().getMethod();
        if (requestMethod == null) {
            log.error("Request without method: {}", requestUri);
            return completeUnauthorizedRequest(serverWebExchange);
        }

        if (isPublicEndpointAccess(requestUri)) {
            log.info("Public api: {}", requestUri);

            //set header
            //Nếu null token thì set info trên header là null
            //Nếu có token thì set như bt
            String bearerToken = ServletUtils.getBearerToken(serverWebExchange);
            if (bearerToken == null) {
                log.info("User just access a public API: {}", requestUri);
                serverWebExchange = setRequestHeaders(serverWebExchange,null, null);
                return webFilterChain.filter(serverWebExchange);
            }

            // Insert userId into request header for each secured request

            String userId = String.valueOf(jwtTokenUtils.getUserIdFromToken(serverWebExchange));
            String email = jwtTokenUtils.getEmailFromToken(serverWebExchange);

            serverWebExchange = setRequestHeaders(serverWebExchange,userId, email);

            return webFilterChain.filter(serverWebExchange);
        }

        //lấy token để kiểm tra
        HttpHeaders headers = serverWebExchange.getRequest().getHeaders();
        String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);

        log.info("Private api: {}", requestUri);
        if (StringUtils.isBlank(authHeader)) {
            return completeUnauthorizedRequest(serverWebExchange);
        }

        ServerWebExchange finalServerWebExchange = serverWebExchange;
        return jwtService
                .verifyToken(authHeader)
                .flatMap(verify -> {
                    if (verify) {
                        String userIdVerify = String.valueOf(jwtTokenUtils.getUserIdFromToken(finalServerWebExchange));
                        String emailVerify = jwtTokenUtils.getEmailFromToken(finalServerWebExchange);

                        if (userIdVerify == null && emailVerify == null) {
                            log.error("Not found userId or wallet in the access token {}");
                            return completeUnauthorizedRequest(finalServerWebExchange);
                        }

                        setRequestHeaders(finalServerWebExchange,userIdVerify, emailVerify);

                        return webFilterChain.filter(finalServerWebExchange);
                    }
                    return completeUnauthorizedRequest(finalServerWebExchange);
                });
    }

    private Mono<Void> completeUnauthorizedRequest(ServerWebExchange serverWebExchange) {
        serverWebExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return serverWebExchange.getResponse().setComplete();
    }

    private boolean isPublicEndpointAccess(String requestUri) {
        boolean isPermitted = false;
        if (!CollectionUtils.isEmpty(routingProperties.getPublicApis())) {
            for (String healthCheckApi : routingProperties.getPublicApis()) {
                if (requestUri.matches(healthCheckApi)) {
                    isPermitted = true;
                    break;
                }
            }
        }
        return isPermitted;
    }

    private boolean isInternalNotAllowed(String requestUri) {
        boolean isNotAllowed = false;
        if (!CollectionUtils.isEmpty(routingProperties.getInternalApis())) {
            for (String healthCheckApi : routingProperties.getInternalApis()) {
                if (requestUri.matches(healthCheckApi)) {
                    isNotAllowed = true;
                    break;
                }
            }
        }
        return isNotAllowed;
    }

    ServerWebExchange setRequestHeaders(ServerWebExchange serverWebExchange,
                                        String userId, String email) {
        ServerHttpRequest mutateRequest = serverWebExchange.getRequest().mutate()
                .header("user_id", userId)
                .header("email", email)
                .build();

        setAccessControlHeaders(serverWebExchange);

        return serverWebExchange.mutate().request(mutateRequest).build();
    }

    //Hàm này set thêm vào header (có cũng đc ko cũng ko sao)
    private void setAccessControlHeaders(ServerWebExchange serverWebExchange) {
        HttpHeaders headers = serverWebExchange.getResponse().getHeaders();
        headers.add(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                serverWebExchange.getRequest().getHeaders().getFirst("Origin"));
        headers.add(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, "withCredentials, Content-Type, Authorization");
        headers.add(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, "GET, PUT, POST, PATCH, DELETE, OPTIONS, HEAD");
        headers.add(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
    }


}
