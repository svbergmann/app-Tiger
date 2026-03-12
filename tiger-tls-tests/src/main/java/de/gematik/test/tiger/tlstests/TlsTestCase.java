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
import java.util.Locale;

/** Enumerates the TLS checks currently bundled with the Tiger TLS test runner. */
public enum TlsTestCase {
  HANDSHAKE("handshake"),
  SUPPORTS_TLS_1_2("supports-tls-1.2"),
  SUPPORTS_TLS_1_3("supports-tls-1.3"),
  PRESENTS_CERTIFICATE("presents-certificate"),
  CERTIFICATE_CURRENTLY_VALID("certificate-currently-valid");

  private final String token;

  TlsTestCase(String token) {
    this.token = token;
  }

  /**
   * Returns the external token used in configuration and TGR steps.
   *
   * @return the lowercase token of the test case
   */
  public String token() {
    return token;
  }

  /**
   * Resolves a test case name in a case-insensitive, separator-insensitive way.
   *
   * @param token the external token or enum name
   * @return the matching test case
   */
  public static TlsTestCase fromToken(String token) {
    final String normalized = normalize(token);
    return Arrays.stream(values())
        .filter(
            value ->
                normalize(value.token).equals(normalized)
                    || normalize(value.name()).equals(normalized))
        .findFirst()
        .orElseThrow(
            () -> new IllegalArgumentException("Unknown TLS test case: " + token));
  }

  private static String normalize(String token) {
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("TLS test case token must not be blank");
    }
    return token.replaceAll("[^A-Za-z0-9]+", "_").toUpperCase(Locale.ROOT);
  }
}
