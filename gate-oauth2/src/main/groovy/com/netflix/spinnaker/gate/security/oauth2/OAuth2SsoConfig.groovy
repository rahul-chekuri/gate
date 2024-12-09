/*
 * Copyright 2016 Google, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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

package com.netflix.spinnaker.gate.security.oauth2

import com.netflix.spinnaker.gate.config.AuthConfig
import com.netflix.spinnaker.gate.security.AllowedAccountsSupport
import com.netflix.spinnaker.gate.security.SpinnakerAuthConfig
import com.netflix.spinnaker.security.User
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.SecurityFilterChain
import org.springframework.session.web.http.DefaultCookieSerializer
import org.springframework.stereotype.Component

@Configuration
@SpinnakerAuthConfig
@EnableWebSecurity
@EnableConfigurationProperties
class OAuth2SsoConfig {
  @Autowired
  DefaultCookieSerializer defaultCookieSerializer

  @Autowired
  AuthConfig authConfig

  @Autowired
  AllowedAccountsSupport allowedAccountsSupport

  @Autowired
  UserInfoRequirements userInfoRequirements

  Converter<OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> authenticationResultConverter(){
    return (authenticationResult) -> new OAuth2AuthenticationToken(mapToSpinnakerUser(authenticationResult.getPrincipal()), authenticationResult.getAuthorities(),
      authenticationResult.getClientRegistration().getRegistrationId())
  }

  private OAuth2User mapToSpinnakerUser(OAuth2User principal) {
    return new OAuth2SpinnakerUser(principal, userInfoRequirements)
  }

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    defaultCookieSerializer.setSameSite(null)
    authConfig.configure(http)

    SecurityFilterChain filterChain = http
      .oauth2Client (Customizer.withDefaults())
      .oauth2Login (Customizer.withDefaults()).build()

    filterChain.getFilters().stream().filter(f  -> f instanceof OAuth2LoginAuthenticationFilter).findFirst().map(OAuth2LoginAuthenticationFilter.class::cast).ifPresent(f -> f.setAuthenticationResultConverter(authenticationResultConverter()))
    return filterChain
  }

  private class OAuth2SpinnakerUser extends User implements OAuth2User {
    OAuth2SpinnakerUser(OAuth2User principal, UserInfoRequirements userInfoRequirements) {
      Map<String, Object> details = principal.getAttributes()
      String username = details.get(userInfoRequirements.get("username")).toString()
      List<String> roles = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()
      setUsername(username)
      setEmail(details.get(userInfoRequirements.get("email")).toString())
      setFirstName(details.get(userInfoRequirements.get("firstName")).toString())
      setLastName(details.get(userInfoRequirements.get("lastName")).toString())
      setRoles(roles)
      setAllowedAccounts(allowedAccountsSupport.filterAllowedAccounts(username, roles))
    }

    @Override
    Map<String, Object> getAttributes() {
      return Map.of()
    }

    @Override
    List<? extends GrantedAuthority> getAuthorities() {
      return List.of()
    }

    @Override
    String getName() {
      return ""
    }
  }

  @Component
  @ConfigurationProperties("spring.security.oauth2.user-info-requirements")
  static class UserInfoRequirements extends HashMap<String, String> {
  }
}
