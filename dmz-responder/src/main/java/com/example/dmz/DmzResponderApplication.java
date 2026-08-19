package com.example.dmz;

import com.example.dmz.config.ResponderProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(ResponderProperties.class)
public class DmzResponderApplication {

    public static void main(String[] args) {
        SpringApplication.run(DmzResponderApplication.class, args);
    }
}
