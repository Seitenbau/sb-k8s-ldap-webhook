package baubau.kube.auth;

import baubau.kube.auth.model.AuthPost;
import baubau.kube.auth.model.Spec;
import baubau.kube.auth.service.JWT;
import com.google.gson.Gson;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(locations = "/test.properties")
public class ApplicationTests
{
  @Autowired
  private MockMvc mvc;

  private JWT jwt = new JWT();

  @Before
  public void setKeyPath()
  {
    jwt.setPUBLIC_KEY_PATH("src/test/java/baubau/kube/auth/test_public_key.pem");
    jwt.setPRIVATE_KEY_PATH("src/test/java/baubau/kube/auth/test_private_key_pkcs8.pem");
  }

  @Test
  public void healthIsAvailable() throws Exception
  {
    mvc.perform(get("/health")).andExpect(status().isOk());
  }

  @Test
  public void authTest() throws Exception
  {
    AuthPost post = new AuthPost();
    post.setSpec(new Spec());
    post.getSpec().setToken(jwt.buildToken("usernotdefined", "issuer"));
    Gson gson = new Gson();

    mvc.perform(post("/authn").contentType(MediaType.APPLICATION_JSON_VALUE).content(gson.toJson(post)))
       .andExpect(status().isOk())
       .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE))
       .andExpect(jsonPath("$.kind", is("TokenReview")))
       .andExpect(jsonPath("$.status.authenticated", is(false)));
  }
}
