package tien.baseproject.gatewayservice.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import tien.baseproject.gatewayservice.constant.TokenField;

import java.text.ParseException;
import java.util.Date;
import java.util.Objects;

@Component
@Slf4j
public class JwtTokenUtils {

    @SneakyThrows
    public Long getUserIdFromToken(ServerWebExchange serverWebExchange) {
        JWTClaimsSet claimsSet = getClaims(serverWebExchange);
        return (Long) claimsSet.getClaim(TokenField.USER_ID);
    }

    @SneakyThrows
    public String getEmailFromToken(ServerWebExchange serverWebExchange) {
        JWTClaimsSet claimsSet = getClaims(serverWebExchange);
        return (String) claimsSet.getClaim(TokenField.EMAIL);
    }

    private JWTClaimsSet getClaims(ServerWebExchange serverWebExchange) throws ParseException ,JOSEException {
        String token = ServletUtils.getBearerToken(serverWebExchange);
        JWSObject jwsObject = JWSObject.parse(Objects.requireNonNull(token));
        JWTClaimsSet claimsSet = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
        Date expiration = claimsSet.getExpirationTime();
        if (expiration != null && expiration.before(new Date())) {
            throw new JOSEException("Token is expired");
        }
        return claimsSet;
    }
}
