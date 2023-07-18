package tien.baseproject.gatewayservice.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class BaseResponse {
    private String message = "successfully";
    private Integer code = 200;
    private String data;

}
