package com.example.iam;

import com.example.iam.config.IamProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TempConfigController {

    private final IamProperties properties;

    public TempConfigController(IamProperties properties) {
        this.properties = properties;
    }

    @GetMapping("/temp/config")
    public Map<String, Object> show() {
        return Map.of(
                "issuer", properties.getIssuer(),
                "loginUrl", properties.getLoginUrl(),
                "accessTtl", properties.getJwt().getAccessTokenTtl().toString(),
                "minLength", properties.getPassword().getMinLength(),
                "cookieSecure", properties.getCookie().isSecure()
        );
    }
}