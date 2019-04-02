package baubau.kube.auth.controller;

import baubau.kube.auth.model.AuthPost;
import baubau.kube.auth.model.AuthResponse;
import baubau.kube.auth.model.User;
import baubau.kube.auth.service.JWT;
import baubau.kube.auth.service.LDAP;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.inject.Inject;

import static baubau.kube.auth.utils.Utils.getMethodName;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@Slf4j
public class AuthController
{
  private final JWT jwt;

  private final LDAP ldap;

  @Inject
  public AuthController(JWT jwt, LDAP ldap)
  {
    this.jwt = jwt;
    this.ldap = ldap;
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
