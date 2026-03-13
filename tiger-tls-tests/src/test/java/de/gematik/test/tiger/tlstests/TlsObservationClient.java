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
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * Real TLS client helper used by server-observation tests.
 */
final class TlsObservationClient {

  private final TlsClientProbeSupport tlsClientProbeSupport = new TlsClientProbeSupport();

  /**
   * Connects to one running server-side observation server and completes the TLS handshake.
   *
   * @param bindHost local bind host of the observation server
   * @param port local port of the observation server
   * @param trustedServerIdentity trust anchor used by the test client
   * @param clientIdentity optional client certificate presented during the handshake
   * @param sniHostName requested SNI host name
   * @param enabledProtocols optional client protocol restrictions
   * @param enabledCipherSuites optional client cipher-suite restrictions
   * @param applicationProtocols optional client ALPN application protocols
   * @throws Exception if the TLS handshake fails
   */
  void connect(
      String bindHost,
      int port,
      TigerConfigurationPkiIdentity trustedServerIdentity,
      TigerConfigurationPkiIdentity clientIdentity,
      String sniHostName,
      String[] enabledProtocols,
      String[] enabledCipherSuites,
      String[] applicationProtocols)
      throws Exception {
    final TlsConnectionConfiguration configuration =
        TlsConnectionConfiguration.defaults()
            .withTrustAllCertificates(false)
            .withTrustStoreIdentity(trustedServerIdentity)
            .withClientIdentity(clientIdentity);
    final SSLContext sslContext = tlsClientProbeSupport.buildSslContext(configuration);
    final TlsTestTarget target = new TlsTestTarget(bindHost, port, sniHostName);
    try (SSLSocket socket =
        tlsClientProbeSupport.openSocket(
            sslContext, target, configuration, enabledProtocols, enabledCipherSuites)) {
      if (applicationProtocols != null && applicationProtocols.length > 0) {
        final SSLParameters sslParameters = socket.getSSLParameters();
        sslParameters.setApplicationProtocols(applicationProtocols.clone());
        socket.setSSLParameters(sslParameters);
      }
      socket.startHandshake();
    }
  }
}
