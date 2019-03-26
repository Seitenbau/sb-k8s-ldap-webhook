package baubau.kube.auth.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class User
{
  private String username;
  private String uid;
  private List<String> groups;

  public User(String username, String uid, List<String> groups)
  {
    this.username = username;
    this.uid = uid;
    this.groups = groups;
  }
}
