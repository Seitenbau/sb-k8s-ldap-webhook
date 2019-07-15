package com.seitenbau.k8s.auth.controller;

import com.seitenbau.k8s.auth.model.AuthPost;
import com.seitenbau.k8s.auth.model.AuthResponse;
import com.seitenbau.k8s.auth.model.User;
import com.seitenbau.k8s.auth.service.LDAP;
import com.seitenbau.k8s.jwt.service.JWT;
import com.seitenbau.k8s.jwt.service.KeyReader;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.inject.Inject;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.TimeUnit;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@Slf4j
public class AuthController
{

  private final LDAP ldap;

  private KeyReader keyReader;

  private JWT jwt;

  private MeterRegistry meterRegistry;

  @Inject
  public AuthController(LDAP ldap, @Value("${public_key_path}") String public_key_path, MeterRegistry meterRegistry)
  {
    this.ldap = ldap;
    this.keyReader = new KeyReader();

    try
    {
      jwt = new JWT(keyReader.readPublicKey(public_key_path));
    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e)
    {
      log.error(e.getMessage(), e);
    }

    this.meterRegistry = meterRegistry;
  }

  @RequestMapping(value = "/healthz", produces = TEXT_PLAIN_VALUE)
  public String health()
  {
    meterRegistry.counter("http.requests", "path", "/healthz", "code", Integer.toString(HttpStatus.OK.value()))
                 .increment();
    return "OK\n";
  }

  @RequestMapping(method = RequestMethod.POST, value = "authn", produces = APPLICATION_JSON_VALUE)
  public AuthResponse authn(@RequestBody AuthPost authPost)
  {
    long startTime = System.nanoTime();

    final String methodName = "authn";
    log.trace("Start: '" + methodName + "' with parameter authToken: " + authPost.toString());

    AuthResponse response = new AuthResponse();

    Jws<Claims> jws;
    try
    {
      jws = jwt.validateToken(authPost.getSpec().getToken());
      User user = ldap.getUserWithGroups(jws.getBody().getSubject());
      if (user != null)
      {
        response.authenticated(true);
        response.getStatus().put("user", user);
        meterRegistry.counter("authentication", "success", "true", "reason", "").increment();
      }
    }
    catch (ExpiredJwtException e)
    {
      log.error("token is expired", e);
      meterRegistry.counter("authentication", "success", "false", "reason", "token_expiration").increment();
    }
    catch (JwtException e)
    {
      log.error("failed to authenticate user", e);
      meterRegistry.counter("authentication", "success", "false", "reason", "user_authentication_failure").increment();
    }
    catch (Exception e)
    {
      log.error("authentication failed", e);
      meterRegistry.counter("authentication", "success", "false", "reason", "unknown").increment();
    }

    log.trace("End: '" + methodName + "' returning " + response);
    meterRegistry.counter("http.requests", "path", "/authn", "code", Integer.toString(HttpStatus.OK.value()))
                 .increment();
    meterRegistry.timer("http.request.duration", "path", "/authn")
                 .record(System.nanoTime() - startTime, TimeUnit.NANOSECONDS);

    return response;
  }
}
