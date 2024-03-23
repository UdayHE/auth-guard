package io.github.UdayHE.authguard.health;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.Map;

import static java.lang.System.currentTimeMillis;
import static java.time.Instant.ofEpochMilli;
import static java.util.Map.entry;
import static java.util.Map.ofEntries;

/**
 * @author udayhegde
 */
@Component
@Slf4j
public class CustomHealthIndicator implements HealthIndicator {

    private Long serviceStartTime = 0L;

    @PostConstruct
    public void init() {
        serviceStartTime = currentTimeMillis();
        log.info("voice-vault start time:{}", serviceStartTime);
    }

    @Override
    public Health health() {
        Map<String, Object> details = ofEntries(
                entry("since", ofEpochMilli(serviceStartTime).toString()),
                entry("now", ofEpochMilli(currentTimeMillis()).toString()));
       return Health.up().withDetails(details).build();

    }
}