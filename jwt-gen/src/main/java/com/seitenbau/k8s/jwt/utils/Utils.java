package com.seitenbau.k8s.jwt.utils;

public class Utils
{
  public static String getMethodName(Object object)
  {
    return object.getClass().getEnclosingMethod().getName();
  }
}