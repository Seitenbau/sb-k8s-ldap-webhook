package com.seitenbau.k8s.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Date;

@NoArgsConstructor
@Slf4j
public class JWT implements Serializable
{
  @Setter
  private PrivateKey privateKey;

  @Setter
  private RSAPublicKey publicKey;

  public JWT(RSAPublicKey publicKey)
  {
    this.publicKey = publicKey;
  }

  public Jws<Claims> validateToken(String token)
  {
    final String methodName = "validateToken";
    log.trace("Start: '" + methodName + "' with parameter token: " + token);

    log.trace("End: " + methodName);
    return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
  }

  public String buildToken(String subject, String issuer, int time, String jti)
  {
    final String methodName = "build Token";
    log.trace("Start: " + methodName);

    String result = null;
    try
    {
      result = Jwts.builder()
                   .setId(jti)
                   .setSubject(subject)
                   .setIssuer(issuer)
                   .setIssuedAt(new Date())
                   .setExpiration(calculateExpirationDate(time))
                   .signWith(privateKey)
                   .compact();
    }
    catch (Exception e)
    {
      log.error("could not build token", e);
    }

    log.trace("End: " + methodName);
    return result;
  }

  private Date calculateExpirationDate(int time)
  {
    Calendar c = Calendar.getInstance();
    c.setTime(new Date());
    c.add(Calendar.DATE, time);

    return c.getTime();
  }
}
