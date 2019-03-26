package baubau.kube.auth;

import baubau.kube.auth.service.JWT;

public class JWTToken
{
  public static void main(String[] args)
  {
    JWT jwt = new JWT();
    jwt.setPRIVATE_KEY_PATH(args[2]);
    System.out.println(jwt.buildToken(args[0], args[1]));
  }
}
