package com.seitenbau.k8s.auth.service;

import com.seitenbau.k8s.auth.model.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import static com.seitenbau.k8s.auth.utils.Utils.getMethodName;

@Service
@Slf4j
public class LDAP
{
  @Value("${initial_context_factory}")
  private String INITIAL_CONTEXT_FACTORY;

  @Value("${security_authentication}")
  private String SECURITY_AUTHENTICATION;

  @Value("${security_principal}")
  private String SECURITY_PRINCIPAL;

  @Value("${security_credentials}")
  private String SECURITY_CREDENTIALS;

  @Value("${provider_url}")
  private String PROVIDER_URL;

  @Value("${referral}")
  private String REFERRAL;

  @Value("${ldap_user_search_base}")
  private String LDAP_USER_SEARCH_BASE;

  @Value("${ldap_group_search_base}")
  private String LDAP_GROUP_SEARCH_BASE;

  @Value("${ldap_user_name_attribute}")
  private String LDAP_USER_NAME_ATTRIBUTE;

  @Value("${ldap_user_uid_attribute}")
  private String LDAP_USER_UID_ATTRIBUTE;

  @Value("${ldap_group_search_filter}")
  private String LDAP_GROUP_SEARCH_FILTER;

  @Value("${ldap_user_dn_attribute}")
  private String LDAP_USER_DN_ATTRIBUTE;

  public User getUserWithGroups(String name)
  {
    final String methodName = getMethodName(new Object()
    {
    });
    log.trace("Start: '" + methodName + "' with parameter name: " + name);

    LdapContext ctx;
    User user = null;
    try
    {
      Hashtable<String, String> env = new Hashtable<>();
      env.put(Context.INITIAL_CONTEXT_FACTORY, INITIAL_CONTEXT_FACTORY);
      env.put(Context.SECURITY_AUTHENTICATION, SECURITY_AUTHENTICATION);
      env.put(Context.SECURITY_PRINCIPAL, SECURITY_PRINCIPAL);
      env.put(Context.SECURITY_CREDENTIALS, SECURITY_CREDENTIALS);
      env.put(Context.PROVIDER_URL, PROVIDER_URL);
      env.put(Context.REFERRAL, REFERRAL);

      ctx = new InitialLdapContext(env, null);

      SearchControls searchControls = new SearchControls();
      searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

      NamingEnumeration<SearchResult> answer = ctx.search(LDAP_USER_SEARCH_BASE,
                                                          LDAP_USER_NAME_ATTRIBUTE + "=" + name,
                                                          searchControls);

      if (answer.hasMore())
      {
        Attributes attributes = answer.next().getAttributes();
        List<String> groups = new ArrayList<>();

        String username = getValueOfAttribute(attributes, LDAP_USER_NAME_ATTRIBUTE);
        String uid = getValueOfAttribute(attributes, LDAP_USER_UID_ATTRIBUTE);
        String dn = getValueOfAttribute(attributes, LDAP_USER_DN_ATTRIBUTE);

        String filter = LDAP_GROUP_SEARCH_FILTER.replace("{dn}", dn);

        NamingEnumeration<SearchResult> ldapGroups = ctx.search(LDAP_GROUP_SEARCH_BASE, filter, searchControls);

        while (ldapGroups.hasMore())
        {
          Attributes att = ldapGroups.next().getAttributes();
          groups.add(att.get("cn").get().toString());
        }

        user = new User(username, uid, groups);
      }
      else
      {
        log.warn("user " + name + "not found in ldap");
      }
    }
    catch (NamingException nex)
    {
      log.error("Failed to connect to ldap", nex);
    }

    log.trace("End: '" + methodName + "' returning " + user);
    return user;
  }

  private String getValueOfAttribute(Attributes attributes, String key)
  {
    final String methodName = getMethodName(new Object()
    {
    });
    log.trace("Start: '" + methodName + "' with parameter attributes: " + attributes + " key: " + key);

    Attribute attribute = attributes.get(key);
    String result = null;

    if (attribute != null)
    {
      try
      {
        result = String.valueOf(attribute.get());
      }
      catch (NamingException e)
      {
        log.error("Could not find key: " + key, e);
      }
    }
    log.trace("End: '" + methodName + "' returning " + result);
    return result;
  }
}
