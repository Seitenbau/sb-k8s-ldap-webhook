package com.seitenbau.k8s.jwt.test;

import com.seitenbau.k8s.jwt.service.JWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.Before;
import org.junit.Test;

import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.Assert.assertEquals;


public class JWTTests
{
  private JWT jwt = new JWT();

  @Before
  public void setKeyPath()
  {
    jwt.setPUBLIC_KEY_PATH("src/test/java/com/seitenbau/k8s/jwt/test/test_public_key.pem");
    jwt.setPRIVATE_KEY_PATH("src/test/java/com/seitenbau/k8s/jwt/test/test_private_key_pkcs8.pem");
  }

  @Test
  public void validationIsCorrect()
  {
    String subject = "subject";
    String issuer = "issuer";
    String token = jwt.buildToken(subject, issuer, 15);
    Jws<Claims> claims = jwt.validateToken(token);

    assertEquals(claims.getBody().getSubject(), subject);
    assertEquals(claims.getBody().getIssuer(), issuer);
    assertThat("timestamp", new Date(), greaterThan(claims.getBody().getIssuedAt()));
  }

  @Test(expected = SignatureException.class)
  public void validationSignatureIsWrong()
  {
    String fakeToken =
        "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9" + ".eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwiaWF0IjoxNTUyOTA2MDk4fQ" +
        ".MvahXRgo45yZA6ImzhP01PdppBcQCvBnLFVvfR_aeO4mVIQhCI2J1HFnbs3NAavrSDincxMKl62aYS2Uv9Mmh7WgM" +
        "-GcBBW0TAttX7e0rMlvykReU-Nidp2ABJwyudmAckU3T1bnqXwkCSQCg" +
        "-ClR9yqhaA5lH0RtjOOcAyJH3gpD7a5m4MtRc5CTe8Pcc3bxaHN1S8xauIh8fT4SkTQUunwJvdOeQd6MfO" +
        "-MmGTdpqvJiy39m5VdGwYhEDd-sGyfbgjpiTpGZQdsY5Xau_4DF97uY5Wc02EPLdSdEcCyyk5KBz9uhvkqHVnG" +
        "-w5sBSfCfaEiynHhzcWtkPtLZxXUw";
    jwt.validateToken(fakeToken);
  }

  @Test(expected = UnsupportedJwtException.class)
  public void validationAlgorithmIsWrong()
  {
    String fakeToken =
        "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkifQ" +
        ".eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwiaWF0IjoxNTUyOTA2MDk4fQ" +
        ".AO-eixnrGUE-3WkWTRuJuDwXhFSjRMVDhRjFoXPRpCLiAg2DuN94W4wZeGS5UkyuOTSIHcnJ8BVnuxhbTYjVr" +
        "-OoAS_ED4EIaqEIDZ1Ph0BjS-dKecAMGqowA9whzl5grqbXk-zIMgLWAeyGd0AnduyiK7zY3WEfUG5WWgznpnWacATO";
    jwt.validateToken(fakeToken);
  }

  @Test(expected = ExpiredJwtException.class)
  public void validationTokenIsExpired()
  {
    String subject = "subject";
    String issuer = "issuer";
    String token = jwt.buildToken(subject, issuer, -1);
    jwt.validateToken(token);
  }
}