/*
 * Copyright 2020 Amazon.com, Inc.
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

package com.netflix.spinnaker.gate.controllers;

import com.netflix.spinnaker.gate.services.internal.IgorService;
import com.netflix.spinnaker.kork.retrofit.Retrofit2SyncCall;
import io.swagger.v3.oas.annotations.Operation;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.*;

@ConditionalOnProperty("services.igor.enabled")
@RestController
@RequestMapping("/codebuild")
@RequiredArgsConstructor
public class AwsCodeBuildController {

  private final IgorService igorService;

  @Operation(summary = "Retrieve the list of AWS CodeBuild accounts")
  @GetMapping(value = "/accounts")
  List<String> getAccounts() {
    return Retrofit2SyncCall.execute(igorService.getAwsCodeBuildAccounts());
  }

  @Operation(summary = "Retrieve the list of AWS CodeBuild projects in the account")
  @GetMapping(value = "/projects/{account}")
  List<String> getProjects(@PathVariable String account) {
    return Retrofit2SyncCall.execute(igorService.getAwsCodeBuildProjects(account));
  }
}
