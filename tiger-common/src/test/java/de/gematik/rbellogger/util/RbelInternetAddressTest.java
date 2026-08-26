/*
 *
 * Copyright 2021-2026 gematik GmbH
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

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Regression test for TGR-2201: {@link RbelInternetAddress#toInetAddress()} used to call {@link
 * InetAddress#getByName} fresh on every invocation, with no caching. For a hostname that a real DNS
 * server never resolves (as is the case for Tiger's own internal routing names in a mesh setup),
 * every single call paid a full OS resolver timeout - repeated once per message, since {@link
 * RbelSocketAddress#toString()} calls this on every render/log/persist.
 *
 * <p>Measuring wall-clock time here would be unreliable: whether a failing DNS lookup is fast or
 * slow depends entirely on the network the test runs on (this is exactly why the regression sat
 * unnoticed - it does not reproduce on networks with a quick negative DNS response, only ones with
 * a slow one). Instead this asserts the cache is doing its job directly: the underlying resolution
 * runs at most once per hostname, however many times {@code toInetAddress()} is called.
 *
 * <p>{@link RbelInternetAddress#getResolvedHostnameCache()}'s stats are cumulative for the JVM's
 * lifetime - {@code clearResolvedHostnameCache()} evicts entries but does not reset the counters -
 * so every assertion here is a before/after delta, not an absolute count.
 */
class RbelInternetAddressTest {

  @AfterEach
  void clearCache() {
    RbelInternetAddress.clearResolvedHostnameCache();
  }

  @Test
  void repeatedLookupsOfSameUnresolvableHostname_shouldOnlyResolveOnce() {
    // ".invalid" is reserved by RFC 2606 and guaranteed to never resolve
    var address = new RbelInternetAddress("tgr-2201-regression-test.invalid", null);
    long loadsBefore = loadCount();

    for (int i = 0; i < 10; i++) {
      assertThat(address.toInetAddress()).isEmpty();
    }

    assertThat(loadCount() - loadsBefore).isEqualTo(1);
  }

  @Test
  void repeatedLookupsOfSameResolvableHostname_shouldOnlyResolveOnce() {
    var address = new RbelInternetAddress("localhost", null);
    long loadsBefore = loadCount();

    for (int i = 0; i < 10; i++) {
      assertThat(address.toInetAddress()).isPresent();
    }

    assertThat(loadCount() - loadsBefore).isEqualTo(1);
  }

  @Test
  void differentHostnames_shouldEachResolveOnceAndBeCachedIndependently() {
    var first = new RbelInternetAddress("tgr-2201-first.invalid", null);
    var second = new RbelInternetAddress("tgr-2201-second.invalid", null);
    long loadsBefore = loadCount();

    first.toInetAddress();
    first.toInetAddress();
    second.toInetAddress();
    second.toInetAddress();
    second.toInetAddress();

    assertThat(loadCount() - loadsBefore).isEqualTo(2);
  }

  @Test
  void lookupsForAnAlreadyResolvedIpAddress_shouldNeverTouchTheCache() throws Exception {
    var address =
        new RbelInternetAddress("does-not-matter", InetAddress.getByName("127.0.0.1").getAddress());
    long requestsBefore = requestCount();

    for (int i = 0; i < 10; i++) {
      assertThat(address.toInetAddress()).isPresent();
    }

    assertThat(requestCount() - requestsBefore).isZero();
  }

  @Test
  void nullHostname_shouldResolveWithoutTouchingTheCache() {
    var address = new RbelInternetAddress(null, null);
    long requestsBefore = requestCount();

    Optional<InetAddress> result = address.toInetAddress();

    assertThat(result).isPresent();
    assertThat(requestCount() - requestsBefore).isZero();
  }

  private static long loadCount() {
    return RbelInternetAddress.getResolvedHostnameCache().stats().loadCount();
  }

  private static long requestCount() {
    return RbelInternetAddress.getResolvedHostnameCache().stats().requestCount();
  }
}
