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
package de.gematik.test.tiger.tlstests;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/** Bundles a reusable set of TLS checks that can be executed together. */
public enum TlsTestProfile {
  CONNECTIVITY(List.of(TlsTestCase.HANDSHAKE)),
  DEFAULT(
      List.of(
          TlsTestCase.HANDSHAKE,
          TlsTestCase.SUPPORTS_TLS_1_2,
          TlsTestCase.PRESENTS_CERTIFICATE,
          TlsTestCase.CERTIFICATE_CURRENTLY_VALID)),
  STRICT_MODERN(
      List.of(
          TlsTestCase.HANDSHAKE,
          TlsTestCase.SUPPORTS_TLS_1_2,
          TlsTestCase.SUPPORTS_TLS_1_3,
          TlsTestCase.PRESENTS_CERTIFICATE,
          TlsTestCase.CERTIFICATE_CURRENTLY_VALID));

  private final List<TlsTestCase> testCases;

  TlsTestProfile(List<TlsTestCase> testCases) {
    this.testCases = List.copyOf(testCases);
  }

  /**
   * Returns the checks executed by this profile in their execution order.
   *
   * @return the profile checks
   */
  public List<TlsTestCase> testCases() {
    return testCases;
  }

  /**
   * Resolves a profile token in a case-insensitive, separator-insensitive way.
   *
   * @param token the external token or enum name
   * @return the matching profile
   */
  public static TlsTestProfile fromToken(String token) {
    final String normalized = normalize(token);
    return Arrays.stream(values())
        .filter(value -> normalize(value.name()).equals(normalized))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Unknown TLS test profile: " + token));
  }

  private static String normalize(String token) {
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("TLS test profile token must not be blank");
    }
    return token.replaceAll("[^A-Za-z0-9]+", "_").toUpperCase(Locale.ROOT);
  }
}
