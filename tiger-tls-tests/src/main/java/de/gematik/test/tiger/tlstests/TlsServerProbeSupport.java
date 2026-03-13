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
import java.util.Collection;
import java.util.List;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Shared TLS server-side probe utilities used by the observation runner.
 */
final class TlsServerProbeSupport {

  private static final String IN_MEMORY_KEYSTORE_PASSWORD = "changeit";

  /**
   * Creates the helper instance.
   */
  TlsServerProbeSupport() {}

  /**
   * Builds an {@link SSLContext} from the supplied server-side TLS observation configuration.
   *
   * @param configuration server-side TLS observation configuration
   * @return initialized server SSL context
   * @throws Exception if the SSL context or configured identities cannot be initialized
   */
  SSLContext buildSslContext(TlsServerConnectionConfiguration configuration) throws Exception {
    final TigerConfigurationPkiIdentity serverIdentity = configuration.serverIdentity();
    if (serverIdentity == null) {
      throw new IllegalArgumentException("serverIdentity must be configured");
    }
    final SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(
        buildKeyManagers(serverIdentity),
        buildTrustManagers(configuration.trustedClientIdentity()),
        new SecureRandom());
    return sslContext;
  }

  /**
   * Opens and configures an SSL server socket for one observation run.
   *
   * @param sslContext initialized server SSL context
   * @param port requested local TCP port, or {@code 0} for an ephemeral port
   * @param configuration server-side TLS observation configuration
   * @return configured server socket
   * @throws Exception if the server socket cannot be created
   */
  SSLServerSocket openServerSocket(
      SSLContext sslContext, int port, TlsServerConnectionConfiguration configuration)
      throws Exception {
    final SSLServerSocket serverSocket =
        (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket();
    final int timeoutMillis = (int) configuration.timeout().toMillis();
    serverSocket.setSoTimeout(timeoutMillis);
    serverSocket.bind(new InetSocketAddress(configuration.bindHost(), port));

    final SSLParameters sslParameters = serverSocket.getSSLParameters();
    if (!configuration.enabledProtocols().isEmpty()) {
      sslParameters.setProtocols(configuration.enabledProtocols().toArray(String[]::new));
    }
    if (!configuration.enabledCipherSuites().isEmpty()) {
      sslParameters.setCipherSuites(configuration.enabledCipherSuites().toArray(String[]::new));
    }
    if (!configuration.applicationProtocols().isEmpty()) {
      sslParameters.setApplicationProtocols(configuration.applicationProtocols().toArray(String[]::new));
    }
    serverSocket.setSSLParameters(sslParameters);
    serverSocket.setNeedClientAuth(configuration.requireClientCertificate());
    return serverSocket;
  }

  /**
   * Applies the configured SSL parameters to one accepted TLS socket before the handshake starts.
   *
   * @param socket accepted TLS socket
   * @param configuration server-side TLS observation configuration
   * @param observedServerNames mutable SNI capture sink populated during the handshake
   */
  void applyAcceptedSocketConfiguration(
      javax.net.ssl.SSLSocket socket,
      TlsServerConnectionConfiguration configuration,
      Collection<String> observedServerNames) {
    final SSLParameters sslParameters = socket.getSSLParameters();
    if (!configuration.applicationProtocols().isEmpty()) {
      sslParameters.setApplicationProtocols(configuration.applicationProtocols().toArray(String[]::new));
    }
    sslParameters.setSNIMatchers(List.of(new ObservingSniMatcher(observedServerNames)));
    socket.setSSLParameters(sslParameters);
    socket.setUseClientMode(false);
    socket.setNeedClientAuth(configuration.requireClientCertificate());
  }

  /**
   * Builds a simplified session summary from a completed server-side TLS session.
   *
   * @param session completed TLS session
   * @return simplified session summary
   */
  TlsSessionSummary buildSessionSummary(SSLSession session) {
    return new TlsSessionSummary(
        session.getProtocol(), session.getCipherSuite(), extractPeerCertificateSubjects(session));
  }

  /**
   * Extracts the peer certificate subject DNs from a completed server-side TLS session.
   *
   * @param session completed TLS session
   * @return immutable client certificate subject list
   */
  List<String> extractPeerCertificateSubjects(SSLSession session) {
    try {
      final List<String> subjects = new ArrayList<>();
      for (Certificate certificate : session.getPeerCertificates()) {
        subjects.add(((X509Certificate) certificate).getSubjectX500Principal().getName());
      }
      return List.copyOf(subjects);
    } catch (Exception e) {
      return List.of();
    }
  }

  /**
   * Extracts requested SNI server names from a completed TLS session when available.
   *
   * @param session completed TLS session
   * @return immutable requested SNI server-name list
   */
  List<String> extractRequestedServerNames(SSLSession session) {
    if (!(session instanceof ExtendedSSLSession extendedSession)) {
      return List.of();
    }
    final List<SNIServerName> serverNames = extendedSession.getRequestedServerNames();
    if (serverNames == null || serverNames.isEmpty()) {
      return List.of();
    }
    final List<String> requestedServerNames = new ArrayList<>();
    for (SNIServerName serverName : serverNames) {
      requestedServerNames.add(toReadableServerName(serverName));
    }
    return List.copyOf(requestedServerNames);
  }

  /**
   * Returns a readable error message for one exception hierarchy.
   *
   * @param throwable original exception
   * @return most specific error message
   */
  String extractRootCauseMessage(Throwable throwable) {
    Throwable current = throwable;
    while (current.getCause() != null) {
      current = current.getCause();
    }
    return current.getMessage() == null ? current.getClass().getSimpleName() : current.getMessage();
  }

  /**
   * Returns the canonical bind address from one created server socket.
   *
   * @param serverSocket created server socket
   * @return canonical bind address
   */
  String resolveBindAddress(SSLServerSocket serverSocket) {
    final InetAddress bindAddress = serverSocket.getInetAddress();
    return bindAddress == null || bindAddress.isAnyLocalAddress()
        ? "0.0.0.0"
        : bindAddress.getHostAddress();
  }

  /**
   * Builds key managers for the supplied server identity.
   *
   * @param serverIdentity configured server identity
   * @return initialized key managers
   * @throws Exception if the server key material cannot be initialized
   */
  private KeyManager[] buildKeyManagers(TigerConfigurationPkiIdentity serverIdentity)
      throws Exception {
    final TigerPkiIdentity identity =
        new TigerPkiIdentity(serverIdentity.getFileLoadingInformation());
    final KeyStore keyStore = identity.toKeyStoreWithPassword(IN_MEMORY_KEYSTORE_PASSWORD);
    final KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, IN_MEMORY_KEYSTORE_PASSWORD.toCharArray());
    return keyManagerFactory.getKeyManagers();
  }

  /**
   * Builds trust managers for client-certificate validation.
   *
   * @param trustedClientIdentity configured trusted client identity, or {@code null}
   * @return trust managers, or {@code null} to use the platform defaults
   * @throws Exception if the trust store cannot be initialized
   */
  private TrustManager[] buildTrustManagers(TigerConfigurationPkiIdentity trustedClientIdentity)
      throws Exception {
    if (trustedClientIdentity == null) {
      return null;
    }
    final TigerPkiIdentity trustIdentity =
        new TigerPkiIdentity(trustedClientIdentity.getFileLoadingInformation());
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

  /**
   * Converts one requested SNI server name into a readable representation.
   *
   * @param serverName requested SNI server name
   * @return readable requested SNI server name
   */
  private String toReadableServerName(SNIServerName serverName) {
    if (serverName == null) {
      return "";
    }
    return switch (serverName.getType()) {
      case 0 -> new String(serverName.getEncoded(), java.nio.charset.StandardCharsets.US_ASCII);
      default -> "type:%d:%s".formatted(serverName.getType(), toHex(serverName.getEncoded()));
    };
  }

  /**
   * Converts one byte array into a lowercase hexadecimal string.
   *
   * @param input input bytes
   * @return lowercase hexadecimal string
   */
  private String toHex(byte[] input) {
    final StringBuilder builder = new StringBuilder();
    for (byte value : input) {
      builder.append(String.format("%02x", value));
    }
    return builder.toString();
  }

  /**
   * Lenient SNI matcher that records requested server names without constraining the handshake.
   */
  private static final class ObservingSniMatcher extends SNIMatcher {

    private final Collection<String> observedServerNames;

    /**
     * Creates the matcher.
     *
     * @param observedServerNames mutable SNI capture sink
     */
    private ObservingSniMatcher(Collection<String> observedServerNames) {
      super(0);
      this.observedServerNames = observedServerNames;
    }

    /**
     * Records one requested server name and always accepts it.
     *
     * @param serverName requested server name
     * @return always {@code true}
     */
    @Override
    public boolean matches(SNIServerName serverName) {
      if (serverName != null) {
        observedServerNames.add(toReadableServerName(serverName));
      }
      return true;
    }

    /**
     * Converts one requested SNI server name into a readable representation.
     *
     * @param serverName requested SNI server name
     * @return readable requested SNI server name
     */
    private String toReadableServerName(SNIServerName serverName) {
      if (serverName.getType() == 0) {
        return new String(serverName.getEncoded(), java.nio.charset.StandardCharsets.US_ASCII);
      }
      return "type:%d:%s".formatted(serverName.getType(), toHex(serverName.getEncoded()));
    }

    /**
     * Converts one byte array into a lowercase hexadecimal string.
     *
     * @param input input bytes
     * @return lowercase hexadecimal string
     */
    private String toHex(byte[] input) {
      final StringBuilder builder = new StringBuilder();
      for (byte value : input) {
        builder.append(String.format("%02x", value));
      }
      return builder.toString();
    }
  }
}
