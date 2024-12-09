/*
 * Copyright 2021 Salesforce.com, Inc.
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

package com.netflix.spinnaker.gate.security.oauth2

import groovy.util.logging.Slf4j
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.user.DefaultOAuth2User
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import spock.lang.Specification

import static org.mockito.ArgumentMatchers.any
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print

@Slf4j
// AutoConfigureMockMvc is needed here because requests made by MockMvc will need to go through the OAuth2 filter
@AutoConfigureMockMvc
@SpringBootTest
@TestPropertySource(properties = ["spring.config.location=classpath:gate-oauth2-test.yml"])
class OAuth2Spec extends Specification {

  @Autowired
  MockMvc mockMvc

  def "should redirect on oauth2 authentication"() {
    when:
      def result = mockMvc.perform(get("/credentials")
          .header(HttpHeaders.AUTHORIZATION, "Bearer access_token"))
        .andDo(print())
        .andReturn()

    then:
      result.response.getStatus() == 302
  }

  @Configuration
  @EnableWebSecurity
  static class SecurityTestConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
      // @formatter:off
      http
        .authorizeHttpRequests((authorize) -> authorize
          .anyRequest().authenticated()
        )
        .oauth2Login((oauth2) -> oauth2
          .tokenEndpoint((token) -> token.accessTokenResponseClient(mockAccessTokenResponseClient()))
          .userInfoEndpoint((userInfo) -> userInfo.userService(mockUserService()))
        )
      // @formatter:on
      return http.build();
    }

    private static OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> mockAccessTokenResponseClient() {
      OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("access-token-1234")
        .tokenType(OAuth2AccessToken.TokenType.BEARER).expiresIn(60 * 1000).build();

      OAuth2AccessTokenResponseClient tokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
      when(tokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);
      return tokenResponseClient;
    }

    private static OAuth2UserService<OAuth2UserRequest, OAuth2User> mockUserService() {
      Map<String, Object> attributes = new HashMap<>();
      attributes.put("id", "joeg");
      attributes.put("first-name", "Joe");
      attributes.put("last-name", "Grandja");
      attributes.put("email", "joeg@springsecurity.io");

      GrantedAuthority authority = new OAuth2UserAuthority(attributes);
      Set<GrantedAuthority> authorities = new HashSet<>();
      authorities.add(authority);

      DefaultOAuth2User user = new DefaultOAuth2User(authorities, attributes, "email");

      OAuth2UserService userService = mock(OAuth2UserService.class);
      when(userService.loadUser(any())).thenReturn(user);
      return userService;
    }

    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository() {
      return new HttpSessionOAuth2AuthorizedClientRepository();
    }

  }
}
