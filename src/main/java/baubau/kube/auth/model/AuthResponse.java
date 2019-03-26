package baubau.kube.auth.model;

import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
public class AuthResponse
{
  private final String apiVersion = "authentication.k8s.io/v1beta1";
  private final String kind = "TokenReview";
  private Map<String, Object> status = new HashMap<>();

  public AuthResponse()
  {
    authenticated(false);
  }

  public void authenticated(Boolean bool)
  {
    status.put("authenticated", bool);

  }
}
