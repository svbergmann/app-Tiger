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
package de.gematik.rbellogger.util;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import de.gematik.test.tiger.common.config.TigerConfigurationKeys;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

@Value
@AllArgsConstructor
@Slf4j
public class RbelInternetAddress {

  /**
   * Caches the outcome (success or failure) of resolving a bare hostname via {@link
   * InetAddress#getByName}. Only the actual DNS-lookup branch of {@link #toInetAddress()} is cached
   * - when an IP address is already known, converting it back to an {@link InetAddress} is a local,
   * non-blocking operation and does not need caching.
   *
   * <p>Both outcomes are cached, including failures: a hostname that Tiger routes internally (like
   * a mesh peer's symbolic name) will never resolve via real DNS, so every uncached call pays a
   * full OS resolver timeout for a lookup that fails the same way every time.
   *
   * <p>The TTL comes from {@code tiger.rbel.dnsCacheTtlSeconds} and defaults to 30s, deliberately
   * shorter than the 10 minutes this started out with: CANOPY ships a 30s DNS TTL, and holding a
   * resolution twenty times longer than that means a host which moves mid-run keeps resolving to
   * its old address. Set it to {@code 0} to disable caching.
   *
   * <p>Built on first use rather than at class-initialisation time, because the configuration is
   * not necessarily loaded yet when this class is first touched.
   */
  static Cache<String, Optional<InetAddress>> getResolvedHostnameCache() {
    return CacheHolder.INSTANCE;
  }

  private static final class CacheHolder {
    private CacheHolder() {}

    static final Cache<String, Optional<InetAddress>> INSTANCE = build();

    private static Cache<String, Optional<InetAddress>> build() {
      int ttlSeconds =
          Math.max(0, TigerConfigurationKeys.RBEL_DNS_CACHE_TTL_SECONDS.getValueOrDefault());
      return CacheBuilder.newBuilder()
          .expireAfterWrite(Duration.ofSeconds(ttlSeconds))
          .maximumSize(10_000)
          .recordStats()
          .build();
    }
  }

  public static void clearResolvedHostnameCache() {
    getResolvedHostnameCache().invalidateAll();
  }

  String hostname;
  byte[] ipAddress;

  /**
   * Named addresses compare by hostname, unnamed ones by bytes, and the two are never equal. See
   * {@link RbelSocketAddress#isSameAddress} for the looser, resolving comparison.
   */
  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof RbelInternetAddress that)) {
      return false;
    }
    if (hostname != null && that.hostname != null) {
      // host names are case-insensitive (RFC 4343)
      return hostname.equalsIgnoreCase(that.hostname);
    }
    if (hostname == null && that.hostname == null) {
      return Arrays.equals(ipAddress, that.ipAddress);
    }
    return false;
  }

  @Override
  public int hashCode() {
    return hostname != null
        ? hostname.toLowerCase(Locale.ROOT).hashCode()
        : Arrays.hashCode(ipAddress);
  }

  public static RbelInternetAddress fromInetAddress(InetAddress ipAddress) {
    return new RbelInternetAddress(
        RbelInternetAddressParser.hostnameWithoutLookup(ipAddress), ipAddress.getAddress());
  }

  /** Renders {@code hostname/ip}, resolving through the TTL cache to fill in a missing IP. */
  @SneakyThrows
  public String toString() {
    val knownIp = ipAddress != null ? InetAddress.getByAddress(ipAddress) : resolveForRendering();
    if (knownIp == null) {
      return hostname;
    }
    if (StringUtils.isBlank(hostname)) {
      return knownIp.getHostAddress();
    }
    return hostname + "/" + knownIp.getHostAddress();
  }

  /** Never let rendering fail on an unresolvable host - it simply prints without the IP. */
  private InetAddress resolveForRendering() {
    if (hostname == null) {
      return null;
    }
    return toInetAddress().orElse(null);
  }

  @SneakyThrows
  public String printValidHostname() {
    if (hostname != null) {
      return hostname;
    } else if (ipAddress != null) {
      return InetAddress.getByAddress(ipAddress).getHostAddress();
    } else {
      return "<unknown-host>";
    }
  }

  /**
   * The address this refers to, carrying the hostname whenever one is known so that a later {@code
   * getHostName()} does not reverse-resolve.
   */
  public Optional<InetAddress> toInetAddress() {
    if (ipAddress != null) {
      try {
        return Optional.of(
            hostname == null
                ? InetAddress.getByAddress(ipAddress)
                : InetAddress.getByAddress(hostname, ipAddress));
      } catch (UnknownHostException e) {
        return Optional.empty();
      }
    }
    if (hostname == null) {
      // InetAddress.getByName(null) is a fast, local special case (loopback address, no network
      // I/O) - nothing to cache.
      return resolveHostname();
    }
    try {
      return getResolvedHostnameCache().get(hostname, this::resolveHostname);
    } catch (ExecutionException e) {
      log.trace("Unexpected error resolving hostname '{}'", hostname, e);
      return Optional.empty();
    }
  }

  private Optional<InetAddress> resolveHostname() {
    try {
      return Optional.ofNullable(hostnameResolver.resolve(hostname));
    } catch (UnknownHostException e) {
      return Optional.empty();
    }
  }

  /**
   * The single point where a hostname becomes an address. Swappable for tests; a test that replaces
   * it must restore it via {@link #resetHostnameResolver()}.
   */
  @FunctionalInterface
  public interface HostnameResolver {
    InetAddress resolve(String hostname) throws UnknownHostException;
  }

  public static final HostnameResolver REAL_RESOLVER = InetAddress::getByName;

  @SuppressWarnings("java:S3008") // not a constant: tests replace it, hence the lower-case name
  private static HostnameResolver hostnameResolver = REAL_RESOLVER;

  public static void setHostnameResolver(HostnameResolver resolver) {
    hostnameResolver = resolver;
    clearResolvedHostnameCache();
  }

  public static void resetHostnameResolver() {
    setHostnameResolver(REAL_RESOLVER);
  }
}
