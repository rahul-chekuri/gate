/*
 * Copyright 2016 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.netflix.spinnaker.gate.controllers

import com.netflix.spinnaker.gate.services.SessionService
import spock.lang.Specification
import spock.lang.Unroll

class AuthControllerSpec extends Specification {
  @Unroll
  def "should validate redirectUrl against deckBaseUrl or redirectHostPattern"() {
    given:
    def autoController = new AuthController(deckBaseUrl, redirectHostPattern, null)

    expect:
    autoController.validDeckRedirect(to) == isValid

    where:
    deckBaseUrl                      | redirectHostPattern | to                               || isValid
    new URL("http://localhost:9000") | null                | "http://localhost:9000"          || true
    new URL("http://localhost:9000") | null                | "http://localhost:8000"          || false
    new URL("http://localhost:9000") | "localhost"         | "http://localhost:8000"          || true     // favor redirectHostPattern if specified
    new URL("http://localhost:9000") | "spinnaker"         | "http://localhost:8000"          || false
    new URL("http://localhost:9000") | "root.net"          | "http://spinnaker.root.net:8000" || false
    new URL("http://localhost:9000") | ".*\\.root\\.net"   | "http://spinnaker.root.net:8000" || true     // redirectHostPattern supports regex
  }

  @Unroll
  def "should delete session tokens cache"() {
    given:
    def sessionServiceMock = Mock(SessionService)
    sessionServiceMock.deleteSpringSessions() >> null

    def authController = new AuthController(null, null, sessionServiceMock)

    when:
    authController.deleteSessionCache()

    then:
    1 * sessionServiceMock.deleteSpringSessions()
  }
}
