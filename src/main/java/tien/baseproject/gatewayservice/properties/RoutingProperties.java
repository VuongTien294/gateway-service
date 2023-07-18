package tien.baseproject.gatewayservice.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "routing", ignoreUnknownFields = false)
@Getter
@Setter
public class RoutingProperties {
    private List<String> publicApis;

    private List<String> internalApis;

    //prefix = 'routing' nghĩa là nó sẽ lấy biến routing trong file application.yml
    //getter sẽ ra đc cái public-apis và internal-apis bên dưới
}
