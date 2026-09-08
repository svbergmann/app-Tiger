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
package de.gematik.rbellogger.data.facet;

import static de.gematik.rbellogger.testutil.RbelElementAssertion.assertThat;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.data.core.RbelSocketAddressFacet;
import de.gematik.rbellogger.util.RbelSocketAddress;
import lombok.val;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class RbelSocketAddressFacetTest {

  @ParameterizedTest
  @CsvSource({"https://foo,foo,443", "http://foo,foo,80", "https://foo:8080,foo,8080"})
  void generateRbelHostnameFacet(String url, String hostname, String port) {
    assertThat(
            RbelSocketAddress.generateFromUrl(url)
                .map(
                    adr ->
                        RbelSocketAddressFacet.buildRbelSocketAddressFacet(new RbelElement(), adr))
                .orElseThrow())
        .hasFacet(RbelSocketAddressFacet.class)
        .hasStringContentEqualToAtPosition("$.domain", hostname)
        .hasStringContentEqualToAtPosition("$.port", port);
  }

  /**
   * Not resolvable, and rejected by the resolver without a DNS round trip. A realistic logical name
   * like "reverseHostname" would cost a multi-second NXDOMAIN lookup per distinct name.
   */
  private static final String LOGICAL_NAME = "my..service";

  private static final String OTHER_LOGICAL_NAME = "my..other-service";

  @ParameterizedTest(name = "[{index}] {0}:{1} and {2}:{3} are the same peer: {4}")
  @CsvSource({
    // the same host, spelled differently, is one peer - this is what message pairing relies on
    "localhost,    8080, 127.0.0.1,          8080, true",
    "127.0.0.1,    8080, localhost,          8080, true",
    "LocalHost,    8080, localhost,          8080, true",
    // the port is part of the identity
    "localhost,    8080, localhost,          9090, false",
    "localhost,    8080, 127.0.0.1,          9090, false",
    // logical names that never resolve are compared by name, ignoring case
    "my..service,  8080, MY..SERVICE,        8080, true",
    "my..service,  8080, my..other-service,  8080, false",
    // a logical name is never the same peer as one that resolves
    "my..service,  8080, localhost,          8080, false"
  })
  void domainAndPortEquals_identifiesPeersByResolvedHostNotBySpelling(
      String domainLeft,
      int portLeft,
      String domainRight,
      int portRight,
      boolean expectedSamePeer) {
    assertThat(facetFor(domainLeft, portLeft).domainAndPortEquals(facetFor(domainRight, portRight)))
        .isEqualTo(expectedSamePeer);
  }

  @Test
  @DisplayName("A message without a usable domain must not break pairing with an exception")
  void domainAndPortEquals_withBlankDomain_shouldNotThrow() {
    assertThatCode(() -> facetFor("", 8080).domainAndPortEquals(facetFor(LOGICAL_NAME, 8080)))
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("Comparing a peer with itself is always true, whatever the domain looks like")
  void domainAndPortEquals_isReflexive() {
    assertThat(
            facetFor(OTHER_LOGICAL_NAME, 443)
                .domainAndPortEquals(facetFor(OTHER_LOGICAL_NAME, 443)))
        .isTrue();
  }

  /**
   * Builds the facet from the raw domain string rather than via {@link RbelSocketAddress}, which
   * would already normalize "127.0.0.1" to "localhost" and hide the aliasing this tests.
   */
  private static RbelSocketAddressFacet facetFor(String domain, int port) {
    val parent = new RbelElement();
    return RbelSocketAddressFacet.builder()
        .port(RbelElement.wrap(parent, port))
        .domain(RbelElement.wrap(parent, domain))
        .build();
  }
}
