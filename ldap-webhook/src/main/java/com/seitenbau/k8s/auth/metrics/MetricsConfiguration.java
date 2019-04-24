package com.seitenbau.k8s.auth.metrics;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.prometheus.PrometheusConfig;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MetricsConfiguration
{

    @Bean
    public MeterRegistry meterRegistry()
    {
        return  new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
    }

}
