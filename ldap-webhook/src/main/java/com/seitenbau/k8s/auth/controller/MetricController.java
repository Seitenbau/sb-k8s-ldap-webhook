package com.seitenbau.k8s.auth.controller;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.inject.Inject;

import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@Slf4j
public class MetricController
{
  private MeterRegistry meterRegistry;

  @Inject
  public MetricController(MeterRegistry meterRegistry)
  {
    this.meterRegistry = meterRegistry;
  }


  @RequestMapping(value = "/metrics", produces = TEXT_PLAIN_VALUE)
  public String metrics()
  {

    meterRegistry.counter("http.requests", "path", "/metrics", "code", Integer.toString(HttpStatus.OK.value()))
                 .increment();
    return ((PrometheusMeterRegistry) meterRegistry).scrape();

  }
}
