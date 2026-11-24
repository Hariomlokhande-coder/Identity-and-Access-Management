package io.github.hariomlokhande.iam;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import io.github.hariomlokhande.iam.config.IamProperties;

@SpringBootApplication
@EnableConfigurationProperties(IamProperties.class)
@EnableScheduling
public class IamApplication {

    public static void main(String[] args) {
        SpringApplication.run(IamApplication.class, args);
    }
}