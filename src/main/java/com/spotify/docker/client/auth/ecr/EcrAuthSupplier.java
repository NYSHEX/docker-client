/*-
 * -\-\-
 * docker-client
 * --
 * Copyright (C) 2018 NYSHEX, LLC
 * --
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -/-/-
 */
    
package com.spotify.docker.client.auth.ecr;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.ecr.AmazonECRAsync;
import com.amazonaws.services.ecr.AmazonECRAsyncClientBuilder;
import com.amazonaws.services.ecr.model.AuthorizationData;
import com.amazonaws.services.ecr.model.GetAuthorizationTokenRequest;
import com.amazonaws.services.ecr.model.GetAuthorizationTokenResult;
import com.spotify.docker.client.auth.RegistryAuthSupplier;
import com.spotify.docker.client.exceptions.DockerException;
import com.spotify.docker.client.messages.RegistryAuth;
import com.spotify.docker.client.messages.RegistryConfigs;

/**
 * @author Peter Savitsky (peter.savitsky@nyshex.com)
 */
public class EcrAuthSupplier implements RegistryAuthSupplier {

  private static final Pattern ECR_REPOSITORY_PATTERN = Pattern
      .compile("([0-9]+)\\.dkr\\.ecr\\..*\\.amazonaws\\.com");

  private final String registryId;
  private final String registryUrl;

  /**
   * @param registryId
   * @param registryUrl
   */
  public EcrAuthSupplier(String registryId, String registryUrl) {
    this.registryId = registryId;
    this.registryUrl = registryUrl;
  }

  @Override
  public RegistryAuth authFor(String imageName) throws DockerException {
    final String[] imageParts = imageName.split("/", 2);
    if (imageParts.length < 2) {
      return null;
    }
    Matcher matcher = ECR_REPOSITORY_PATTERN.matcher(imageParts[0]);
    if (!matcher.matches()) {
      return null;
    }
    if (!matcher.group(1).equals(registryId)) {
      throw new DockerException("Configured registry Id does not match registry id for image");
    }
    final GetAuthorizationTokenResult authorizationToken = getAuthorizationToken();
    return authForAuthenticationToken(authorizationToken.getAuthorizationData().get(0));
  }

  @Override
  public RegistryAuth authForSwarm() {
    final GetAuthorizationTokenResult authorizationToken = getAuthorizationToken();
    return authForAuthenticationToken(authorizationToken.getAuthorizationData().get(0));
  }

  @Override
  public RegistryConfigs authForBuild() {
    final Map<String, RegistryAuth> configs = new HashMap<>();
    final GetAuthorizationTokenResult authorizationToken = getAuthorizationToken();
    RegistryAuth auth = authForAuthenticationToken(authorizationToken.getAuthorizationData().get(0));
    configs.put(registryUrl, auth);
    return RegistryConfigs.create(configs);
  }

  private GetAuthorizationTokenResult getAuthorizationToken() {
    AmazonECRAsync client = AmazonECRAsyncClientBuilder.standard() //
        .withCredentials(new ProfileCredentialsProvider()) //
        .build();
    List<String> registryIds = new ArrayList<>();
    registryIds.add(registryId);
    GetAuthorizationTokenRequest tokenRequest = new GetAuthorizationTokenRequest();
    tokenRequest.setRegistryIds(registryIds);
    return client.getAuthorizationToken(tokenRequest);
  }

  private RegistryAuth authForAuthenticationToken(AuthorizationData authorizationData) {
    return RegistryAuth.builder() //
        .username("AWS") //
        .password(authorizationData.getAuthorizationToken()) //
        .build();
  }

}
