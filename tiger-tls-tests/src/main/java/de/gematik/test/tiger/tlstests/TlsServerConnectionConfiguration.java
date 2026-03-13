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
 * Configures how Tiger should expose itself as a TLS server while observing one DUT client
 * connection.
 *
 * @param bindHost local bind host used by the observation server
 * @param serverIdentity server certificate and key presented to the DUT client
 * @param trustedClientIdentity optional trust anchor used to validate client certificates
 * @param requireClientCertificate whether the DUT client must present a certificate
 * @param timeout timeout used for accepting and awaiting one client connection
 * @param enabledProtocols optional server protocol restrictions
 * @param enabledCipherSuites optional server cipher-suite restrictions
 * @param applicationProtocols optional ALPN application protocols exposed by the observation server
 */
public record TlsServerConnectionConfiguration(
    String bindHost,
    TigerConfigurationPkiIdentity serverIdentity,
    TigerConfigurationPkiIdentity trustedClientIdentity,
    boolean requireClientCertificate,
    Duration timeout,
    List<String> enabledProtocols,
    List<String> enabledCipherSuites,
    List<String> applicationProtocols) {

  /**
   * Creates a validated server-side TLS observation configuration.
   *
   * @param bindHost local bind host used by the observation server
   * @param serverIdentity server certificate and key presented to the DUT client
   * @param trustedClientIdentity optional trust anchor used to validate client certificates
   * @param requireClientCertificate whether the DUT client must present a certificate
   * @param timeout timeout used for accepting and awaiting one client connection
   * @param enabledProtocols optional server protocol restrictions
   * @param enabledCipherSuites optional server cipher-suite restrictions
   * @param applicationProtocols optional ALPN application protocols exposed by the observation server
   */
  public TlsServerConnectionConfiguration {
    if (bindHost == null || bindHost.isBlank()) {
      throw new IllegalArgumentException("bindHost must not be blank");
    }
    if (timeout == null || timeout.isZero() || timeout.isNegative()) {
      throw new IllegalArgumentException("timeout must be greater than zero");
    }
    if (requireClientCertificate && trustedClientIdentity == null) {
      throw new IllegalArgumentException(
          "trustedClientIdentity must be configured when client certificates are required");
    }
    enabledProtocols = List.copyOf(enabledProtocols == null ? List.of() : enabledProtocols);
    enabledCipherSuites =
        List.copyOf(enabledCipherSuites == null ? List.of() : enabledCipherSuites);
    applicationProtocols =
        List.copyOf(applicationProtocols == null ? List.of() : applicationProtocols);
  }

  /**
   * Returns the permissive default server-side TLS observation configuration.
   *
   * @return permissive default server-side TLS observation configuration
   */
  public static TlsServerConnectionConfiguration defaults() {
    return new TlsServerConnectionConfiguration(
        "127.0.0.1", null, null, false, Duration.ofSeconds(10), List.of(), List.of(), List.of());
  }

  /**
   * Returns a copy with the supplied bind host.
   *
   * @param newBindHost new bind host
   * @return copied configuration with the updated bind host
   */
  public TlsServerConnectionConfiguration withBindHost(String newBindHost) {
    return new TlsServerConnectionConfiguration(
        newBindHost,
        serverIdentity,
        trustedClientIdentity,
        requireClientCertificate,
        timeout,
        enabledProtocols,
        enabledCipherSuites,
        applicationProtocols);
  }

  /**
   * Returns a copy with the supplied server identity.
   *
   * @param newServerIdentity new server identity
   * @return copied configuration with the updated server identity
   */
  public TlsServerConnectionConfiguration withServerIdentity(
      TigerConfigurationPkiIdentity newServerIdentity) {
    return new TlsServerConnectionConfiguration(
        bindHost,
        newServerIdentity,
        trustedClientIdentity,
        requireClientCertificate,
        timeout,
        enabledProtocols,
        enabledCipherSuites,
        applicationProtocols);
  }

  /**
   * Returns a copy with the supplied trusted client identity.
   *
   * @param newTrustedClientIdentity new trusted client identity
   * @return copied configuration with the updated trusted client identity
   */
  public TlsServerConnectionConfiguration withTrustedClientIdentity(
      TigerConfigurationPkiIdentity newTrustedClientIdentity) {
    return new TlsServerConnectionConfiguration(
        bindHost,
        serverIdentity,
        newTrustedClientIdentity,
        requireClientCertificate,
        timeout,
        enabledProtocols,
        enabledCipherSuites,
        applicationProtocols);
  }

  /**
   * Returns a copy with the supplied client-certificate requirement.
   *
   * @param newRequireClientCertificate new client-certificate requirement
   * @return copied configuration with the updated client-certificate requirement
   */
  public TlsServerConnectionConfiguration withRequireClientCertificate(
      boolean newRequireClientCertificate) {
    return new TlsServerConnectionConfiguration(
        bindHost,
        serverIdentity,
        trustedClientIdentity,
        newRequireClientCertificate,
        timeout,
        enabledProtocols,
        enabledCipherSuites,
        applicationProtocols);
  }

  /**
   * Returns a copy with the supplied timeout.
   *
   * @param newTimeout new timeout
   * @return copied configuration with the updated timeout
   */
  public TlsServerConnectionConfiguration withTimeout(Duration newTimeout) {
    return new TlsServerConnectionConfiguration(
        bindHost,
        serverIdentity,
        trustedClientIdentity,
        requireClientCertificate,
        newTimeout,
        enabledProtocols,
        enabledCipherSuites,
        applicationProtocols);
  }

  /**
   * Returns a copy with the supplied protocol list.
   *
   * @param newEnabledProtocols new protocol list
   * @return copied configuration with the updated protocol list
   */
  public TlsServerConnectionConfiguration withEnabledProtocols(List<String> newEnabledProtocols) {
    return new TlsServerConnectionConfiguration(
        bindHost,
        serverIdentity,
        trustedClientIdentity,
        requireClientCertificate,
        timeout,
        newEnabledProtocols,
        enabledCipherSuites,
        applicationProtocols);
  }

  /**
   * Returns a copy with the supplied cipher-suite list.
   *
   * @param newEnabledCipherSuites new cipher-suite list
   * @return copied configuration with the updated cipher-suite list
   */
  public TlsServerConnectionConfiguration withEnabledCipherSuites(
      List<String> newEnabledCipherSuites) {
    return new TlsServerConnectionConfiguration(
        bindHost,
        serverIdentity,
        trustedClientIdentity,
        requireClientCertificate,
        timeout,
        enabledProtocols,
        newEnabledCipherSuites,
        applicationProtocols);
  }

  /**
   * Returns a copy with the supplied ALPN application protocols.
   *
   * @param newApplicationProtocols new ALPN application protocols
   * @return copied configuration with the updated ALPN application protocols
   */
  public TlsServerConnectionConfiguration withApplicationProtocols(
      List<String> newApplicationProtocols) {
    return new TlsServerConnectionConfiguration(
        bindHost,
        serverIdentity,
        trustedClientIdentity,
        requireClientCertificate,
        timeout,
        enabledProtocols,
        enabledCipherSuites,
        newApplicationProtocols);
  }
}
