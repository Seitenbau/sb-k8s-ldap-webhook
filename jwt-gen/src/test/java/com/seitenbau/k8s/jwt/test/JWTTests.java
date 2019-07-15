package com.seitenbau.k8s.jwt.test;

import com.seitenbau.k8s.jwt.service.JWT;
import com.seitenbau.k8s.jwt.service.KeyReader;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.Assert.assertEquals;


public class JWTTests
{
  private JWT jwt = new JWT();

  private KeyReader keyReader = new KeyReader();

  @Before
  public void setKeyPath()
  {
    try
    {
      jwt.setPublicKey(keyReader.readPublicKey("src/test/java/com/seitenbau/k8s/jwt/test/test_public_key.pem"));
      jwt.setPrivateKey(keyReader.readPrivateKey(
          "src/test/java/com/seitenbau/k8s/jwt/test/test_private_key_pkcs8" + ".pem"));

    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e)
    {
      e.printStackTrace();
    }
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
        "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwiaWF0IjoxNTUyOTA2MDk4fQ" +
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

  @Test(expected = UnsupportedJwtException.class)
  public void validationInjectedNoneAlgorithmNoSignatureIsWrong()
  {
    String algNoneToken =
        "eyJhbGciOiJub25lIn0=" +
        ".eyJqdGkiOiI0OTQ4OTE5NTEiLCJzdWIiOiJtc3RlbmtlIiwiaXNzIjoiYmF1YmF1IiwiaWF0IjoxNTU5NjU1MDkwLCJ" +
        "leHAiOjE1OTA0MTM0OTB9.";
    jwt.validateToken(algNoneToken);
  }

  @Test(expected = MalformedJwtException.class)
  public void validationInjectedNoneAlgorithmWithSignatureIsWrong()
  {
    String algNoneToken =
        "eyJhbGciOiJub25lIn0=" +
        ".eyJqdGkiOiI0OTA5NzA3NTkiLCJzdWIiOiJtc3RlbmtlIiwiaXNzIjoiYmF1YmF1IiwiaWF0IjoxNTYzMTg5NzY1LCJleHAiOjE1OTM5NDgx" +
        "NjV9.JuBdQT8gBOrRL4dwYrYnkwu2JsoBDymgU4f7m6zOaB0DFLV1w7Gj2EvGC24uVdmk7nO5G-aKIjOkT5mpI0HuPLh11l9_WmMhg4FJGR" +
        "lrdsDZjYWVUlWPLeEfamww9O66MRJ7hHk80jxdIiiuOicCD1Wlpg8ewM5CUkJF57ze8b0y7PQAcJFuFhXGmk_BjDwYh_E38yP2tc2D6EQHB25" +
        "VnplhPgoES07JhBnL5uAzUWnQhcZ4FXL75L7dg1tFKW7HiT5097oNbIQU1liEmRNLIHzT46hkcBwSpJh" +
        "-GnwISAGSqU8fjcID18voSaJ2643pnM5oxPeV-enTTMQWlLE_DA";
    jwt.validateToken(algNoneToken);
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