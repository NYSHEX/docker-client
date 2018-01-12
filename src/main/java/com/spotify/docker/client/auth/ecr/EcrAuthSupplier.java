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

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.util.encoders.Base64;

import com.amazonaws.auth.AWSCredentialsProviderChain;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
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
  private static final String ECR_REPOSITORY_FORMAT = "%s%s.dkr.ecr.%s.amazonaws.com"; 

  private final String registryId;
  private final String region;

  /**
   * @param registryId
   * @param region
   */
  public EcrAuthSupplier(String registryId, String region) {
    this.registryId = registryId;
    this.region = region;
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
  public RegistryAuth authForSwarm() throws DockerException {
    final GetAuthorizationTokenResult authorizationToken = getAuthorizationToken();
    return authForAuthenticationToken(authorizationToken.getAuthorizationData().get(0));
  }

  @Override
  public RegistryConfigs authForBuild() throws DockerException {
    final Map<String, RegistryAuth> configs = new HashMap<>();
    final GetAuthorizationTokenResult authorizationToken = getAuthorizationToken();
    RegistryAuth auth = authForAuthenticationToken(authorizationToken.getAuthorizationData().get(0));
    configs.put(getRepositoryAddress(), auth);
    return RegistryConfigs.create(configs);
  }

  private GetAuthorizationTokenResult getAuthorizationToken() {
      //TODO: add support for different credential providers
    AmazonECRAsync client = AmazonECRAsyncClientBuilder.standard() //
        .withCredentials(new AWSCredentialsProviderChain(
            // First we'll check for EC2 instance profile credentials.
            InstanceProfileCredentialsProvider.getInstance(),
            // If we're not on an EC2 instance, fall back to checking for
            // credentials in the local credentials profile file.
            new ProfileCredentialsProvider()))
        .withRegion(region) //
        .build();
    List<String> registryIds = new ArrayList<>();
    registryIds.add(registryId);
    GetAuthorizationTokenRequest tokenRequest = new GetAuthorizationTokenRequest();
    tokenRequest.setRegistryIds(registryIds);
    return client.getAuthorizationToken(tokenRequest);
  }

  private RegistryAuth authForAuthenticationToken(AuthorizationData authorizationData) throws DockerException {
    byte[] decodedToken = Base64.decode(authorizationData.getAuthorizationToken());
    String decodedTokenString;
    try {
      decodedTokenString = new String(decodedToken, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new DockerException("Error decoding AWS ECR token and username");
    }
    String[] usernameAndToken = decodedTokenString.split(":");
    return RegistryAuth.builder() //
        .username(usernameAndToken[0]) //
        .password(usernameAndToken[1]) //
        .serverAddress(getServerAddress()) //
        .build();
  }
  
  private String getServerAddress() {
      return String.format(ECR_REPOSITORY_FORMAT, "https://", registryId, region);
  } 
  
  private String getRepositoryAddress() {
      return String.format(ECR_REPOSITORY_FORMAT, "", registryId, region);
  }

}
