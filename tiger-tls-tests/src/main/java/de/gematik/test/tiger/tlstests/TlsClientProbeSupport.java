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
import de.gematik.test.tiger.common.pki.TigerPkiIdentity;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Shared TLS client-side probe utilities used by the runner and compliance scanner.
 */
final class TlsClientProbeSupport {

  private static final String IN_MEMORY_KEYSTORE_PASSWORD = "changeit";

  /**
   * Creates a helper instance.
   */
  TlsClientProbeSupport() {}

  /**
   * Builds an {@link SSLContext} from the supplied Tiger TLS connection configuration.
   *
   * @param configuration TLS connection configuration
   * @return initialized SSL context
   * @throws Exception if the SSL context or the configured identities cannot be initialized
   */
  SSLContext buildSslContext(TlsConnectionConfiguration configuration) throws Exception {
    final SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(
        buildKeyManagers(configuration.clientIdentity()),
        buildTrustManagers(configuration),
        new SecureRandom());
    return sslContext;
  }

  /**
   * Opens and configures an SSL socket for one probe attempt without triggering the handshake.
   *
   * @param sslContext initialized SSL context
   * @param target probed target endpoint
   * @param configuration TLS connection configuration
   * @param enabledProtocols protocol override for this probe, or {@code null} to use the configuration defaults
   * @param enabledCipherSuites cipher-suite override for this probe, or {@code null} to use the configuration defaults
   * @return connected and configured socket ready for {@link SSLSocket#startHandshake()}
   * @throws Exception if the socket cannot be created or configured
   */
  SSLSocket openSocket(
      SSLContext sslContext,
      TlsTestTarget target,
      TlsConnectionConfiguration configuration,
      String[] enabledProtocols,
      String[] enabledCipherSuites)
      throws Exception {
    final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
    final int timeoutMillis = (int) configuration.timeout().toMillis();
    socket.setSoTimeout(timeoutMillis);
    socket.connect(new InetSocketAddress(target.host(), target.port()), timeoutMillis);

    final SSLParameters sslParameters = socket.getSSLParameters();
    final String[] protocolsToUse = resolveEnabledProtocols(configuration, enabledProtocols);
    if (protocolsToUse != null) {
      sslParameters.setProtocols(protocolsToUse);
    }
    final String[] cipherSuitesToUse =
        resolveEnabledCipherSuites(configuration, enabledCipherSuites);
    if (cipherSuitesToUse != null) {
      sslParameters.setCipherSuites(cipherSuitesToUse);
    }
    if (configuration.hostnameVerification()) {
      sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
    }
    if (!target.effectiveSniHostName().isBlank() && !isIpAddress(target.effectiveSniHostName())) {
      sslParameters.setServerNames(List.of(new SNIHostName(target.effectiveSniHostName())));
    }
    socket.setSSLParameters(sslParameters);
    return socket;
  }

  /**
   * Builds a simplified session summary from a completed TLS session.
   *
   * @param session completed TLS session
   * @return simplified session summary
   * @throws Exception if peer certificate extraction fails
   */
  TlsSessionSummary buildSessionSummary(SSLSession session) throws Exception {
    final List<X509Certificate> peerCertificates = extractPeerCertificates(session);
    return new TlsSessionSummary(
        session.getProtocol(),
        session.getCipherSuite(),
        peerCertificates.stream().map(cert -> cert.getSubjectX500Principal().getName()).toList());
  }

  /**
   * Extracts the peer certificate chain from a completed TLS session.
   *
   * @param session completed TLS session
   * @return immutable peer certificate chain
   * @throws Exception if the peer certificates cannot be converted
   */
  List<X509Certificate> extractPeerCertificates(SSLSession session) throws Exception {
    final List<X509Certificate> certificates = new ArrayList<>();
    for (Certificate certificate : session.getPeerCertificates()) {
      certificates.add((X509Certificate) certificate);
    }
    return List.copyOf(certificates);
  }

  /**
   * Resolves the effective protocol list for one probe attempt.
   *
   * @param configuration TLS connection configuration
   * @param probeSpecificProtocols protocol override for this probe, or {@code null}
   * @return effective protocol list, or {@code null} to leave provider defaults untouched
   */
  String[] resolveEnabledProtocols(
      TlsConnectionConfiguration configuration, String[] probeSpecificProtocols) {
    if (probeSpecificProtocols != null) {
      return probeSpecificProtocols;
    }
    return configuration.enabledProtocols().isEmpty()
        ? null
        : configuration.enabledProtocols().toArray(String[]::new);
  }

  /**
   * Resolves the effective cipher-suite list for one probe attempt.
   *
   * @param configuration TLS connection configuration
   * @param probeSpecificCipherSuites cipher-suite override for this probe, or {@code null}
   * @return effective cipher-suite list, or {@code null} to leave provider defaults untouched
   */
  String[] resolveEnabledCipherSuites(
      TlsConnectionConfiguration configuration, String[] probeSpecificCipherSuites) {
    if (probeSpecificCipherSuites != null) {
      return probeSpecificCipherSuites;
    }
    return configuration.enabledCipherSuites().isEmpty()
        ? null
        : configuration.enabledCipherSuites().toArray(String[]::new);
  }

  /**
   * Extracts the most specific error message from an exception hierarchy.
   *
   * @param throwable original exception
   * @return root-cause message or class name
   */
  String extractRootCauseMessage(Throwable throwable) {
    Throwable current = throwable;
    while (current.getCause() != null) {
      current = current.getCause();
    }
    return current.getMessage() == null ? current.getClass().getSimpleName() : current.getMessage();
  }

  /**
   * Builds key managers for a configured client identity.
   *
   * @param clientIdentity configured client identity or {@code null}
   * @return key managers, or {@code null} when no client identity is configured
   * @throws Exception if the client key material cannot be initialized
   */
  private KeyManager[] buildKeyManagers(TigerConfigurationPkiIdentity clientIdentity)
      throws Exception {
    if (clientIdentity == null) {
      return null;
    }

    final TigerPkiIdentity identity =
        new TigerPkiIdentity(clientIdentity.getFileLoadingInformation());
    final KeyStore keyStore = identity.toKeyStoreWithPassword(IN_MEMORY_KEYSTORE_PASSWORD);
    final KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, IN_MEMORY_KEYSTORE_PASSWORD.toCharArray());
    return keyManagerFactory.getKeyManagers();
  }

  /**
   * Builds trust managers for the requested server-certificate validation strategy.
   *
   * @param configuration TLS connection configuration
   * @return trust managers, or {@code null} to use the platform defaults
   * @throws Exception if a configured trust store cannot be initialized
   */
  private TrustManager[] buildTrustManagers(TlsConnectionConfiguration configuration)
      throws Exception {
    if (configuration.trustAllCertificates()) {
      return new TrustManager[] {new TrustAllX509TrustManager()};
    }

    if (configuration.trustStoreIdentity() != null) {
      final TigerPkiIdentity trustIdentity =
          new TigerPkiIdentity(configuration.trustStoreIdentity().getFileLoadingInformation());
      final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
      trustStore.load(null, null);
      int entryCounter = 0;
      for (Certificate certificate : trustIdentity.buildChainWithCertificate()) {
        trustStore.setCertificateEntry("trusted-%d".formatted(entryCounter++), certificate);
      }
      final TrustManagerFactory trustManagerFactory =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init(trustStore);
      return trustManagerFactory.getTrustManagers();
    }

    return null;
  }

  /**
   * Determines whether a given host token is an IP address and therefore should not be sent as DNS
   * SNI.
   *
   * @param hostname host token to inspect
   * @return {@code true} when the token resolves to the same textual IP address
   */
  private boolean isIpAddress(String hostname) {
    try {
      return hostname.equals(InetAddress.getByName(hostname).getHostAddress());
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Trust manager implementation that accepts any certificate chain.
   */
  private static final class TrustAllX509TrustManager implements X509TrustManager {

    /**
     * Accepts any client certificate chain.
     *
     * @param chain presented client chain
     * @param authType requested authentication type
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    /**
     * Accepts any server certificate chain.
     *
     * @param chain presented server chain
     * @param authType requested authentication type
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    /**
     * Returns the accepted issuer list for the permissive trust manager.
     *
     * @return empty issuer list
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}
