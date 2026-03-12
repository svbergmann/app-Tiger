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

import de.gematik.test.tiger.common.pki.TigerConfigurationPkiIdentity;
import java.time.Duration;

/**
 * Configures how a TLS test run should authenticate itself and validate the peer.
 *
 * @param trustAllCertificates if {@code true}, the runner accepts any server certificate chain
 * @param hostnameVerification if {@code true}, endpoint identification is enforced for HTTPS
 * @param trustStoreIdentity optional identity whose certificate chain is used as trust anchor
 * @param clientIdentity optional client certificate presented during the handshake
 * @param timeout socket connect and read timeout used by the runner
 */
public record TlsConnectionConfiguration(
    boolean trustAllCertificates,
    boolean hostnameVerification,
    TigerConfigurationPkiIdentity trustStoreIdentity,
    TigerConfigurationPkiIdentity clientIdentity,
    Duration timeout) {

  /**
   * Creates a validated connection configuration.
   *
   * @param trustAllCertificates if {@code true}, the runner accepts any server certificate chain
   * @param hostnameVerification if {@code true}, endpoint identification is enforced for HTTPS
   * @param trustStoreIdentity optional identity whose certificate chain is used as trust anchor
   * @param clientIdentity optional client certificate presented during the handshake
   * @param timeout socket connect and read timeout used by the runner
   */
  public TlsConnectionConfiguration {
    if (timeout == null || timeout.isZero() || timeout.isNegative()) {
      throw new IllegalArgumentException("timeout must be greater than zero");
    }
  }

  /**
   * Returns the default connection configuration for TLS probing.
   *
   * <p>The default is intentionally permissive so tests can inspect non-public certificates
   * without requiring pre-installed trust material.
   *
   * @return a permissive default configuration
   */
  public static TlsConnectionConfiguration defaults() {
    return new TlsConnectionConfiguration(true, false, null, null, Duration.ofSeconds(10));
  }
}
