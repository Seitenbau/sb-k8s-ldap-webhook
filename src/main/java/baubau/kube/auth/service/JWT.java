package baubau.kube.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import static baubau.kube.auth.utils.Utils.getMethodName;

@Service
@Slf4j
public class JWT
{
  @Setter
  private String PRIVATE_KEY_PATH;

  @Value("${public_key_path}")
  @Setter
  private String PUBLIC_KEY_PATH;

  private PrivateKey readPrivateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException
  {
    final String methodName = getMethodName(new Object()
    {
    });
    log.trace("Start: " + methodName);
    String privateKeyContent = new String(Files.readAllBytes(Paths.get(PRIVATE_KEY_PATH)));

    privateKeyContent = privateKeyContent.replaceAll("\\n", "")
                                         .replace("-----BEGIN PRIVATE KEY-----", "")
                                         .replace("-----END PRIVATE KEY-----", "");

    KeyFactory kf = KeyFactory.getInstance("RSA");

    PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
    PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

    log.trace("End: " + methodName);
    return privKey;
  }

  private RSAPublicKey readPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
  {
    final String methodName = getMethodName(new Object()
    {
    });
    log.trace("Start: " + methodName);

    String publicKeyContent = new String(Files.readAllBytes(Paths.get(PUBLIC_KEY_PATH)));
    publicKeyContent = publicKeyContent.replaceAll("\\n", "")
                                       .replace("-----BEGIN PUBLIC KEY-----", "")
                                       .replace("-----END PUBLIC KEY-----", "");
    KeyFactory kf = KeyFactory.getInstance("RSA");

    X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));

    log.trace("End: " + methodName);
    return (RSAPublicKey) kf.generatePublic(keySpecX509);
  }

  public Jws<Claims> validateToken(String token)
  {
    final String methodName = getMethodName(new Object()
    {
    });
    log.trace("Start: '" + methodName + "' with parameter token: " + token);

    PublicKey publicKey = null;
    try
    {
      publicKey = readPublicKey();
    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NullPointerException e)
    {
      log.error("could not load public key pem file", e);
    }

    log.trace("End: " + methodName);
    return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
  }

  public String buildToken(String subject, String issuer)
  {
    final String methodName = getMethodName(new Object()
    {
    });
    log.trace("Start: " + methodName);

    String result = null;
    try
    {
      result = Jwts.builder()
                   .setSubject(subject)
                   .setIssuer(issuer)
                   .setIssuedAt(new Date())
                   .signWith(readPrivateKey())
                   .compact();
    }
    catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e)
    {
      log.error("could not build token", e);
    }

    log.trace("Start: " + methodName);
    return result;
  }
}
