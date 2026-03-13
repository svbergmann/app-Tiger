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
import java.util.List;

/**
 * Configures how a TLS test run should authenticate itself and validate the peer.
 *
 * @param trustAllCertificates if {@code true}, the runner accepts any server certificate chain
 * @param hostnameVerification if {@code true}, endpoint identification is enforced for HTTPS
 * @param trustStoreIdentity optional identity whose certificate chain is used as trust anchor
 * @param clientIdentity optional client certificate presented during the handshake
 * @param timeout socket connect and read timeout used by the runner
 * @param enabledProtocols optional list of protocol versions exposed to the peer
 * @param enabledCipherSuites optional list of cipher suites exposed to the peer
 */
public record TlsConnectionConfiguration(
    boolean trustAllCertificates,
    boolean hostnameVerification,
    TigerConfigurationPkiIdentity trustStoreIdentity,
    TigerConfigurationPkiIdentity clientIdentity,
    Duration timeout,
    List<String> enabledProtocols,
    List<String> enabledCipherSuites) {

  /**
   * Creates a validated connection configuration.
   *
   * @param trustAllCertificates if {@code true}, the runner accepts any server certificate chain
   * @param hostnameVerification if {@code true}, endpoint identification is enforced for HTTPS
   * @param trustStoreIdentity optional identity whose certificate chain is used as trust anchor
   * @param clientIdentity optional client certificate presented during the handshake
   * @param timeout socket connect and read timeout used by the runner
   * @param enabledProtocols optional list of protocol versions exposed to the peer
   * @param enabledCipherSuites optional list of cipher suites exposed to the peer
   */
  public TlsConnectionConfiguration {
    if (timeout == null || timeout.isZero() || timeout.isNegative()) {
      throw new IllegalArgumentException("timeout must be greater than zero");
    }
    enabledProtocols = List.copyOf(enabledProtocols == null ? List.of() : enabledProtocols);
    enabledCipherSuites =
        List.copyOf(enabledCipherSuites == null ? List.of() : enabledCipherSuites);
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
    return new TlsConnectionConfiguration(
        true, false, null, null, Duration.ofSeconds(10), List.of(), List.of());
  }

  /**
   * Returns a copy with the provided trust-all setting.
   *
   * @param newTrustAllCertificates new trust-all value
   * @return copied configuration with updated trust-all setting
   */
  public TlsConnectionConfiguration withTrustAllCertificates(boolean newTrustAllCertificates) {
    return new TlsConnectionConfiguration(
        newTrustAllCertificates,
        hostnameVerification,
        trustStoreIdentity,
        clientIdentity,
        timeout,
        enabledProtocols,
        enabledCipherSuites);
  }

  /**
   * Returns a copy with the provided hostname verification setting.
   *
   * @param newHostnameVerification new hostname verification value
   * @return copied configuration with updated hostname verification
   */
  public TlsConnectionConfiguration withHostnameVerification(boolean newHostnameVerification) {
    return new TlsConnectionConfiguration(
        trustAllCertificates,
        newHostnameVerification,
        trustStoreIdentity,
        clientIdentity,
        timeout,
        enabledProtocols,
        enabledCipherSuites);
  }

  /**
   * Returns a copy with the provided trust store identity.
   *
   * @param newTrustStoreIdentity new trust store identity
   * @return copied configuration with updated trust store identity
   */
  public TlsConnectionConfiguration withTrustStoreIdentity(
      TigerConfigurationPkiIdentity newTrustStoreIdentity) {
    return new TlsConnectionConfiguration(
        trustAllCertificates,
        hostnameVerification,
        newTrustStoreIdentity,
        clientIdentity,
        timeout,
        enabledProtocols,
        enabledCipherSuites);
  }

  /**
   * Returns a copy with the provided client identity.
   *
   * @param newClientIdentity new client identity
   * @return copied configuration with updated client identity
   */
  public TlsConnectionConfiguration withClientIdentity(
      TigerConfigurationPkiIdentity newClientIdentity) {
    return new TlsConnectionConfiguration(
        trustAllCertificates,
        hostnameVerification,
        trustStoreIdentity,
        newClientIdentity,
        timeout,
        enabledProtocols,
        enabledCipherSuites);
  }

  /**
   * Returns a copy with the provided timeout.
   *
   * @param newTimeout new timeout
   * @return copied configuration with updated timeout
   */
  public TlsConnectionConfiguration withTimeout(Duration newTimeout) {
    return new TlsConnectionConfiguration(
        trustAllCertificates,
        hostnameVerification,
        trustStoreIdentity,
        clientIdentity,
        newTimeout,
        enabledProtocols,
        enabledCipherSuites);
  }

  /**
   * Returns a copy with the provided protocol list.
   *
   * @param newEnabledProtocols new protocol list
   * @return copied configuration with updated protocol list
   */
  public TlsConnectionConfiguration withEnabledProtocols(List<String> newEnabledProtocols) {
    return new TlsConnectionConfiguration(
        trustAllCertificates,
        hostnameVerification,
        trustStoreIdentity,
        clientIdentity,
        timeout,
        newEnabledProtocols,
        enabledCipherSuites);
  }

  /**
   * Returns a copy with the provided cipher suite list.
   *
   * @param newEnabledCipherSuites new cipher suite list
   * @return copied configuration with updated cipher suite list
   */
  public TlsConnectionConfiguration withEnabledCipherSuites(List<String> newEnabledCipherSuites) {
    return new TlsConnectionConfiguration(
        trustAllCertificates,
        hostnameVerification,
        trustStoreIdentity,
        clientIdentity,
        timeout,
        enabledProtocols,
        newEnabledCipherSuites);
  }
}
