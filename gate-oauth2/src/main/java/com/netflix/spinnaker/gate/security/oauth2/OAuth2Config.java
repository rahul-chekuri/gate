/*
 * Copyright 2024 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.gate.security.oauth2;

import com.netflix.spinnaker.gate.config.AuthConfig;
import com.netflix.spinnaker.gate.security.AllowedAccountsSupport;
import com.netflix.spinnaker.gate.security.SpinnakerAuthConfig;
import com.netflix.spinnaker.security.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

//@Configuration
//@SpinnakerAuthConfig
//@EnableWebSecurity
//@EnableConfigurationProperties
////@Conditional(OAuth2Config.IsOAuthEnabled.class)
public class OAuth2Config {

  @Autowired
  DefaultCookieSerializer defaultCookieSerializer;

  @Autowired
  AuthConfig authConfig;

  @Autowired
  AllowedAccountsSupport allowedAccountsSupport;

  @Autowired
  UserInfoRequirements userInfoRequirements;

  Converter<OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> authenticationResultConverter(){
    return (authenticationResult) -> new OAuth2AuthenticationToken(mapToSpinnakerUser(authenticationResult.getPrincipal()), authenticationResult.getAuthorities(),
      authenticationResult.getClientRegistration().getRegistrationId());
  }

  private OAuth2User mapToSpinnakerUser(OAuth2User principal) {
    return new OAuth2SpinnakerUser(principal, userInfoRequirements);
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    defaultCookieSerializer.setSameSite(null);
    authConfig.configure(http);

    SecurityFilterChain filterChain = http
      .oauth2Client (Customizer.withDefaults())
      .oauth2Login (Customizer.withDefaults()).build();

    filterChain.getFilters().stream().filter(f  -> f instanceof OAuth2LoginAuthenticationFilter).findFirst().map(OAuth2LoginAuthenticationFilter.class::cast).ifPresent(f -> f.setAuthenticationResultConverter(authenticationResultConverter()));
    return filterChain;
  }

  private class OAuth2SpinnakerUser extends User implements OAuth2User {
    public OAuth2SpinnakerUser(OAuth2User principal, UserInfoRequirements userInfoRequirements) {
      Map<String, Object> details = principal.getAttributes();
      String username = details.get(userInfoRequirements.get("username")).toString();
      List<String> roles = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
      setUsername(username);
      setEmail(details.get(userInfoRequirements.get("email")).toString());
      setFirstName(details.get(userInfoRequirements.get("firstName")).toString());
      setLastName(details.get(userInfoRequirements.get("lastName")).toString());
      setRoles(roles);
      setAllowedAccounts(allowedAccountsSupport.filterAllowedAccounts(username, roles));
    }

    @Override
    public Map<String, Object> getAttributes() {
      return Map.of();
    }

    @Override
    public List<? extends GrantedAuthority> getAuthorities() {
      return List.of();
    }

    @Override
    public String getName() {
      return "";
    }
  }

  @Component
  @ConfigurationProperties("spring.security.oauth2.user-info-requirements")
  static class UserInfoRequirements extends HashMap<String, String> {
  }

  public static class IsOAuthEnabled implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
      Environment env = context.getEnvironment();
      String firstClientID = env.getProperty("spring.security.oauth2.client.registration");
      return firstClientID != null && !firstClientID.isEmpty() ;
    }
  }
}
