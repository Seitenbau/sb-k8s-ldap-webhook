package com.seitenbau.k8s.jwt.service;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@NoArgsConstructor
@Slf4j
public class KeyReader
{
  public PrivateKey readPrivateKey(String path) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException
  {
    final String methodName = "readPrivateKey";
    log.trace("Start: " + methodName);

    String privateKeyContent = new String(Files.readAllBytes(Paths.get(path)));

    privateKeyContent = privateKeyContent.replaceAll("\\n", "")
                                         .replaceAll("\\r", "")
                                         .replace("-----BEGIN PRIVATE KEY-----", "")
                                         .replace("-----END PRIVATE KEY-----", "");

    KeyFactory kf = KeyFactory.getInstance("RSA");

    PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
    PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

    log.trace("End: " + methodName);
    return privKey;
  }

  public RSAPublicKey readPublicKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
  {
    final String methodName = "readPublicKey";
    log.trace("Start: " + methodName);

    String publicKeyContent = new String(Files.readAllBytes(Paths.get(path)));
    publicKeyContent = publicKeyContent.replaceAll("\\n", "")
                                       .replaceAll("\\r", "")
                                       .replace("-----BEGIN PUBLIC KEY-----", "")
                                       .replace("-----END PUBLIC KEY-----", "");
    KeyFactory kf = KeyFactory.getInstance("RSA");

    X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));

    log.trace("End: " + methodName);
    return (RSAPublicKey) kf.generatePublic(keySpecX509);
  }
}
