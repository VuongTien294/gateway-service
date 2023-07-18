package tien.baseproject.gatewayservice.util;

import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

public class ServletUtils {
    private static final String USER_ID = "user_id";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String AUTHORIZATION = "authorization";

    public static String getBearerToken(ServerWebExchange serverWebExchange) {
        HttpHeaders headers = serverWebExchange.getRequest().getHeaders();
        String authorizationHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
        String bearerToken = null;
        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
            bearerToken = authorizationHeader.substring(7);
        }
        return bearerToken;
    }
}
