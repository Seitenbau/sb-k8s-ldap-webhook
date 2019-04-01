package baubau.kube.auth.model;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthPost
{
  public String apiVersion = "authentication.k8s.io/v1beta1";
  public String kind = "TokenReview";
  public Spec spec;

  @Override
  public String toString()
  {
    return "AuthPost{" + "apiVersion='" + apiVersion + '\'' + ", kind='" + kind + '\'' + ", spec=" + spec + '}';
  }
}
