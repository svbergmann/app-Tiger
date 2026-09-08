/*
 *
 * Copyright 2021-2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */
package de.gematik.test.tiger.util;

import static de.gematik.test.tiger.common.util.FunctionWithCheckedException.nullOnException;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import java.net.InetAddress;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

public class NoProxyUtils {
  private static final Cache<String, String> RESOLVED_NO_PROXY_HOST_CACHE =
      CacheBuilder.newBuilder()
          .expireAfterWrite(Duration.ofMinutes(10))
          .maximumSize(10_000)
          .build();

  /**
   * Whether traffic to this host has to go through the configured forward proxy, or is listed as
   * bypassing it. {@code remoteAddress.getHostName()} is asked last, and only once there is a name
   * to compare against: it blocks on a reverse lookup, on the netty event loop.
   */
  public static boolean shouldUseProxyForHost(
      InetAddress remoteAddress, List<String> noProxyHosts) {
    if (noProxyHosts == null || noProxyHosts.isEmpty()) {
      return true;
    }
    final List<String> resolvedNoProxyHosts =
        noProxyHosts.stream()
            .map(NoProxyUtils::resolveNoProxyHostName)
            .flatMap(Optional::stream)
            .toList();
    if (resolvedNoProxyHosts.isEmpty()) {
      return true;
    }
    return !resolvedNoProxyHosts.contains(remoteAddress.getHostName());
  }

  static void clearResolvedNoProxyHostCache() {
    RESOLVED_NO_PROXY_HOST_CACHE.invalidateAll();
  }

  static long getResolvedNoProxyHostCacheSize() {
    return RESOLVED_NO_PROXY_HOST_CACHE.size();
  }

  /**
   * The name a {@code noProxyHosts} entry resolves to, remembered for the TTL. Only successes are
   * cached; a failed lookup is retried on the next request.
   */
  private static Optional<String> resolveNoProxyHostName(String noProxyHost) {
    if (noProxyHost == null) {
      return Optional.empty();
    }
    final String trimmedHost = noProxyHost.trim();
    if (trimmedHost.isEmpty()) {
      return Optional.empty();
    }

    final String cachedResult = RESOLVED_NO_PROXY_HOST_CACHE.getIfPresent(trimmedHost);
    if (cachedResult != null) {
      return Optional.of(cachedResult);
    }

    final Optional<String> resolvedHostName =
        Optional.ofNullable(nullOnException(InetAddress::getByName).apply(trimmedHost))
            .map(InetAddress::getHostName);
    resolvedHostName.ifPresent(name -> RESOLVED_NO_PROXY_HOST_CACHE.put(trimmedHost, name));
    return resolvedHostName;
  }
}
