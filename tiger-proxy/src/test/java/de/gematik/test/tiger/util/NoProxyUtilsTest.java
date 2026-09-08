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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.cache.Cache;
import java.net.InetAddress;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class NoProxyUtilsTest {

  @AfterEach
  @SuppressWarnings("unchecked")
  void tearDown() throws Exception {
    getNoProxyResolutionCache().invalidateAll();
  }

  @Test
  void shouldUseProxyForHost_shouldUseProxyWhenNoProxyHostsIsNull() throws Exception {
    assertThat(NoProxyUtils.shouldUseProxyForHost(InetAddress.getByName("localhost"), null))
        .isTrue();
  }

  @Test
  void shouldUseProxyForHost_shouldBypassProxyForMatchingHost() throws Exception {
    assertThat(
            NoProxyUtils.shouldUseProxyForHost(
                InetAddress.getByName("localhost"), List.of("localhost")))
        .isFalse();
  }

  @Test
  void shouldUseProxyForHost_shouldIgnoreUnresolvableNoProxyHostEntries() throws Exception {
    assertThat(
            NoProxyUtils.shouldUseProxyForHost(
                InetAddress.getByName("localhost"), List.of("notresolvable.invalid", "localhost")))
        .isFalse();
  }

  @Test
  void shouldUseProxyForHost_shouldCacheResolvedNoProxyHosts() throws Exception {
    final InetAddress remoteAddress = InetAddress.getByName("localhost");

    assertThat(NoProxyUtils.shouldUseProxyForHost(remoteAddress, List.of(" localhost "))).isFalse();
    assertThat(getNoProxyResolutionCache().size()).isEqualTo(1);

    assertThat(NoProxyUtils.shouldUseProxyForHost(remoteAddress, List.of("localhost"))).isFalse();
    assertThat(getNoProxyResolutionCache().size()).isEqualTo(1);
  }

  @Test
  void unresolvableNoProxyHostsShouldNotBeRememberedAsUnresolvable() throws Exception {
    NoProxyUtils.shouldUseProxyForHost(
        InetAddress.getByName("localhost"), List.of("notresolvable.invalid"));

    assertThat(getNoProxyResolutionCache().size())
        .as("only successful resolutions belong in the cache, so the next call tries again")
        .isZero();
  }

  @Test
  void theRemoteAddressShouldNotBeReverseResolvedWhenThereIsNothingToCompareItTo() {
    final InetAddress remoteAddress = mock(InetAddress.class);
    // stubbed so that calling it is caught by the verify below rather than by an incidental NPE
    when(remoteAddress.getHostName()).thenReturn("some.host.example.com");

    assertThat(NoProxyUtils.shouldUseProxyForHost(remoteAddress, List.of()))
        .as("an empty list means nothing bypasses the proxy")
        .isTrue();
    assertThat(NoProxyUtils.shouldUseProxyForHost(remoteAddress, List.of("notresolvable.invalid")))
        .as("nor does a list whose only entry does not resolve")
        .isTrue();

    verify(remoteAddress, never()).getHostName();
  }

  @SuppressWarnings("unchecked")
  private static Cache<String, ?> getNoProxyResolutionCache() throws Exception {
    final var cacheField = NoProxyUtils.class.getDeclaredField("RESOLVED_NO_PROXY_HOST_CACHE");
    cacheField.setAccessible(true);
    return (Cache<String, ?>) cacheField.get(null);
  }
}
