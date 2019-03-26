package baubau.kube.auth.utils;

public class Utils
{
  public static String getMethodName(Object object)
  {
    return object.getClass().getEnclosingMethod().getName();
  }
}
