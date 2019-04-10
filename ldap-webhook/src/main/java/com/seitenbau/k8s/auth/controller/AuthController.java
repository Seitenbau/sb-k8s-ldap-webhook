package com.seitenbau.k8s.auth.controller;

import com.google.inject.Inject;
import com.seitenbau.k8s.auth.model.AuthPost;
import com.seitenbau.k8s.auth.model.AuthResponse;
import com.seitenbau.k8s.auth.model.User;
import com.seitenbau.k8s.auth.service.LDAP;
import com.seitenbau.k8s.jwt.service.JWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import static com.seitenbau.k8s.jwt.utils.Utils.getMethodName;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@Slf4j
public class AuthController
{

  private final LDAP ldap;

  private JWT jwt;

  @Inject
  public AuthController(LDAP ldap, @Value("${public_key_path}") String public_key_path)
  {
    this.ldap = ldap;
    jwt = new JWT(public_key_path);
  }

  @RequestMapping(value = "/healthz", produces = TEXT_PLAIN_VALUE)
  public String health()
  {
    return "OK\n";
  }

  @RequestMapping(method = RequestMethod.POST, value = "authn", produces = APPLICATION_JSON_VALUE)
  public AuthResponse authn(@RequestBody AuthPost authPost)
  {
    final String methodName = getMethodName(new Object()
    {
    });
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
      }
    }
    catch (ExpiredJwtException e)
    {
      log.error("token is expired", e);
    }
    catch (JwtException e)
    {
      log.error("failed to authenticate user", e);
    }
    catch (Exception e)
    {
      log.error("authentication failed", e);
    }

    log.trace("End: '" + methodName + "' returning " + response);
    return response;
  }
}
