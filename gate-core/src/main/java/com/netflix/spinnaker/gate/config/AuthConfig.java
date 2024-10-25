/*
 * Copyright 2016 Netflix, Inc.
 * Copyright 2023 Apple, Inc.
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

package com.netflix.spinnaker.gate.config;

import com.netflix.spinnaker.fiat.shared.FiatClientConfigurationProperties;
import com.netflix.spinnaker.fiat.shared.FiatPermissionEvaluator;
import com.netflix.spinnaker.fiat.shared.FiatStatus;
import com.netflix.spinnaker.gate.filters.FiatSessionFilter;
import com.netflix.spinnaker.gate.services.ServiceAccountFilterConfigProps;
import com.netflix.spinnaker.kork.annotations.NonnullByDefault;
import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Configuration
@EnableConfigurationProperties({
  ServiceConfiguration.class,
  ServiceAccountFilterConfigProps.class,
  FiatClientConfigurationProperties.class,
  DynamicRoutingConfigProperties.class
})
@NonnullByDefault
@RequiredArgsConstructor
public class AuthConfig {
  private final PermissionRevokingLogoutSuccessHandler permissionRevokingLogoutSuccessHandler;
  private final FiatStatus fiatStatus;
  private final FiatPermissionEvaluator permissionEvaluator;

  @Setter(
      onMethod_ = {@Autowired},
      onParam_ = {@Value("${security.debug:false}")})
  private boolean securityDebug;

  @Setter(
      onMethod_ = {@Autowired},
      onParam_ = {@Value("${fiat.session-filter.enabled:true}")})
  private boolean fiatSessionFilterEnabled;

  @Setter(
      onMethod_ = {@Autowired},
      onParam_ = {@Value("${security.webhooks.default-auth-enabled:false}")})
  private boolean webhookDefaultAuthEnabled;

  @Bean
  public WebSecurityCustomizer securityDebugCustomizer() {
    return web -> web.debug(securityDebug);
  }

  public void configure(HttpSecurity http) throws Exception {

    http.authorizeHttpRequests(
        (authz) ->
            authz
                .requestMatchers(
                    "/error", "/favicon.ico", "/auth/user", "/health", "/aop-prometheus")
                .permitAll()
                .requestMatchers(HttpMethod.OPTIONS, "/**")
                .permitAll()
                .requestMatchers(PermissionRevokingLogoutSuccessHandler.LOGGED_OUT_URL)
                .permitAll()
                .requestMatchers("/plugins/deck/**")
                .permitAll()
                .requestMatchers(HttpMethod.POST, "/webhooks/**")
                .permitAll()
                .requestMatchers(HttpMethod.POST, "/notifications/callbacks/**")
                .permitAll()
                .requestMatchers(HttpMethod.POST, "/managed/notifications/callbacks/**")
                .permitAll()
                .requestMatchers("/**")
                .authenticated());

    if (fiatSessionFilterEnabled) {
      Filter fiatSessionFilter = new FiatSessionFilter(fiatStatus, permissionEvaluator);
      http.addFilterBefore(fiatSessionFilter, AnonymousAuthenticationFilter.class);
    }

    if (webhookDefaultAuthEnabled) {
      http.authorizeHttpRequests(
          (requests) -> requests.requestMatchers(HttpMethod.POST, "/webhooks/**").authenticated());
    }

    http.logout()
        .logoutUrl("/auth/logout")
        .logoutSuccessHandler(permissionRevokingLogoutSuccessHandler)
        .permitAll()
        .and()
        .csrf()
        .disable();
  }
}
