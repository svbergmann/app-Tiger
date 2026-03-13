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

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.math.BigInteger;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * In-process TLS server used by the TLS test module.
 */
final class TlsTestServer implements AutoCloseable {

  private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();

  /**
   * Controls the certificate validity window of the generated server certificate.
   */
  enum CertificateValidity {
    /** Generates a certificate that is currently valid. */
    VALID,
    /** Generates a certificate that has already expired. */
    EXPIRED
  }

  /**
   * Controls how accepted TLS connections are handled after the initial handshake.
   */
  enum ConnectionBehavior {
    /** Closes the socket immediately after the first handshake. */
    CLOSE_AFTER_HANDSHAKE,
    /** Keeps reading on the socket for a short time so follow-up handshakes can be processed. */
    KEEP_READING_AFTER_HANDSHAKE
  }

  /**
   * Generated PKCS#12 identity used by the test server and optional mTLS client.
   *
   * @param keyStoreFile generated PKCS#12 file
   * @param compactFormat Tiger compact identity token
   * @param keyPair generated key pair
   * @param certificate generated certificate
   */
  record GeneratedIdentity(Path keyStoreFile, String compactFormat, KeyPair keyPair,
                           X509Certificate certificate)
      implements AutoCloseable {

    /**
     * Deletes the generated PKCS#12 file.
     *
     * @throws IOException if the temporary file cannot be removed
     */
    @Override
    public void close() throws IOException {
      Files.deleteIfExists(keyStoreFile);
    }
  }

  private final SSLServerSocket serverSocket;
  private final GeneratedIdentity serverIdentity;
  private final ConnectionBehavior connectionBehavior;
  private final ExecutorService executorService = Executors.newSingleThreadExecutor();

  /**
   * Creates a TLS test server wrapper.
   *
   * @param serverSocket bound server socket
   * @param serverIdentity generated server identity
   * @param connectionBehavior accepted-connection handling mode
   */
  private TlsTestServer(
      SSLServerSocket serverSocket,
      GeneratedIdentity serverIdentity,
      ConnectionBehavior connectionBehavior) {
    this.serverSocket = serverSocket;
    this.serverIdentity = serverIdentity;
    this.connectionBehavior = connectionBehavior;
  }

  /**
   * Starts a simple TLS server that closes the connection after the first handshake.
   *
   * @param validity generated server-certificate validity
   * @param enabledProtocols enabled server protocols
   * @return started TLS test server
   * @throws Exception if the server cannot be started
   */
  static TlsTestServer start(CertificateValidity validity, String... enabledProtocols)
      throws Exception {
    return startInternal(
        createIdentity("Tiger TLS Test Server", validity),
        null,
        enabledProtocols,
        null,
        ConnectionBehavior.CLOSE_AFTER_HANDSHAKE);
  }

  /**
   * Starts a simple TLS server with explicit protocol and cipher-suite restrictions.
   *
   * @param validity generated server-certificate validity
   * @param enabledProtocols enabled server protocols
   * @param enabledCipherSuites enabled server cipher suites
   * @return started TLS test server
   * @throws Exception if the server cannot be started
   */
  static TlsTestServer start(
      CertificateValidity validity, String[] enabledProtocols, String[] enabledCipherSuites)
      throws Exception {
    return startInternal(
        createIdentity("Tiger TLS Test Server", validity),
        null,
        enabledProtocols,
        enabledCipherSuites,
        ConnectionBehavior.CLOSE_AFTER_HANDSHAKE);
  }

  /**
   * Starts a TLS server that keeps connections open long enough for follow-up handshake activity.
   *
   * @param validity generated server-certificate validity
   * @param enabledProtocols enabled server protocols
   * @return started TLS test server
   * @throws Exception if the server cannot be started
   */
  static TlsTestServer startPersistent(CertificateValidity validity, String... enabledProtocols)
      throws Exception {
    return startInternal(
        createIdentity("Tiger TLS Test Server", validity),
        null,
        enabledProtocols,
        null,
        ConnectionBehavior.KEEP_READING_AFTER_HANDSHAKE);
  }

  /**
   * Starts a mutual-TLS server that closes the connection after the first handshake.
   *
   * @param validity generated server-certificate validity
   * @param trustedClientIdentity client identity trusted by the server
   * @param enabledProtocols enabled server protocols
   * @return started TLS test server
   * @throws Exception if the server cannot be started
   */
  static TlsTestServer startMutualTls(
      CertificateValidity validity,
      GeneratedIdentity trustedClientIdentity,
      String... enabledProtocols)
      throws Exception {
    return startInternal(
        createIdentity("Tiger TLS Test Server", validity),
        trustedClientIdentity,
        enabledProtocols,
        null,
        ConnectionBehavior.CLOSE_AFTER_HANDSHAKE);
  }

  /**
   * Starts a mutual-TLS server with explicit protocol and cipher-suite restrictions.
   *
   * @param validity generated server-certificate validity
   * @param trustedClientIdentity client identity trusted by the server
   * @param enabledProtocols enabled server protocols
   * @param enabledCipherSuites enabled server cipher suites
   * @return started TLS test server
   * @throws Exception if the server cannot be started
   */
  static TlsTestServer startMutualTls(
      CertificateValidity validity,
      GeneratedIdentity trustedClientIdentity,
      String[] enabledProtocols,
      String[] enabledCipherSuites)
      throws Exception {
    return startInternal(
        createIdentity("Tiger TLS Test Server", validity),
        trustedClientIdentity,
        enabledProtocols,
        enabledCipherSuites,
        ConnectionBehavior.CLOSE_AFTER_HANDSHAKE);
  }

  /**
   * Generates a reusable PKCS#12 identity.
   *
   * @param commonName certificate common name
   * @param validity generated certificate validity window
   * @return generated identity
   * @throws Exception if the identity cannot be created
   */
  static GeneratedIdentity createIdentity(String commonName, CertificateValidity validity)
      throws Exception {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();
    final X509Certificate certificate = createCertificate(keyPair, commonName, validity);

    final KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);
    keyStore.setKeyEntry(
        "entry", keyPair.getPrivate(), KEYSTORE_PASSWORD, new Certificate[] {certificate});

    final Path keyStoreFile = Files.createTempFile("tiger-tls-test-", ".p12");
    try (var outputStream = Files.newOutputStream(keyStoreFile)) {
      keyStore.store(outputStream, KEYSTORE_PASSWORD);
    }

    return new GeneratedIdentity(
        keyStoreFile, keyStoreFile.toAbsolutePath() + ";changeit;p12", keyPair, certificate);
  }

  /**
   * Returns the TCP port of the started server socket.
   *
   * @return bound TCP port
   */
  int port() {
    return serverSocket.getLocalPort();
  }

  /**
   * Returns the generated server identity in Tiger compact format.
   *
   * @return Tiger compact identity token
   */
  String serverIdentityString() {
    return serverIdentity.compactFormat();
  }

  /**
   * Starts the configured TLS server instance.
   *
   * @param serverIdentity generated server identity
   * @param trustedClientIdentity optional client identity trusted for mTLS
   * @param enabledProtocols enabled server protocols
   * @param enabledCipherSuites enabled server cipher suites
   * @param connectionBehavior accepted-connection handling mode
   * @return started TLS test server
   * @throws Exception if the server cannot be started
   */
  private static TlsTestServer startInternal(
      GeneratedIdentity serverIdentity,
      GeneratedIdentity trustedClientIdentity,
      String[] enabledProtocols,
      String[] enabledCipherSuites,
      ConnectionBehavior connectionBehavior)
      throws Exception {
    try {
      final KeyStore keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(null, null);
      keyStore.setKeyEntry(
          "server",
          serverIdentity.keyPair().getPrivate(),
          KEYSTORE_PASSWORD,
          new Certificate[] {serverIdentity.certificate()});

      final KeyManagerFactory keyManagerFactory =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD);

      final SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(
          keyManagerFactory.getKeyManagers(),
          trustedClientIdentity == null ? null : buildTrustManagers(trustedClientIdentity),
          new SecureRandom());

      final SSLServerSocket serverSocket =
          (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(0);
      serverSocket.setEnabledProtocols(enabledProtocols);
      if (enabledCipherSuites != null && enabledCipherSuites.length > 0) {
        serverSocket.setEnabledCipherSuites(enabledCipherSuites);
      }
      serverSocket.setNeedClientAuth(trustedClientIdentity != null);

      final TlsTestServer tlsTestServer =
          new TlsTestServer(serverSocket, serverIdentity, connectionBehavior);
      tlsTestServer.startAcceptLoop();
      return tlsTestServer;
    } catch (Exception e) {
      serverIdentity.close();
      throw e;
    }
  }

  /**
   * Builds trust managers that trust the supplied generated identity.
   *
   * @param trustedIdentity trusted generated identity
   * @return initialized trust managers
   * @throws Exception if the trust store cannot be created
   */
  private static javax.net.ssl.TrustManager[] buildTrustManagers(GeneratedIdentity trustedIdentity)
      throws Exception {
    final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("trusted", trustedIdentity.certificate());
    final TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);
    return trustManagerFactory.getTrustManagers();
  }

  /**
   * Starts the asynchronous accept loop used by the test server.
   */
  private void startAcceptLoop() {
    executorService.submit(
        () -> {
          while (!serverSocket.isClosed()) {
            try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
              socket.setUseClientMode(false);
              socket.startHandshake();
              handleAcceptedSocket(socket);
            } catch (SocketException e) {
              if (!serverSocket.isClosed()) {
                throw new IllegalStateException("TLS test server accept loop failed", e);
              }
            } catch (Exception e) {
              if (serverSocket.isClosed()) {
                return;
              }
            }
          }
        });
  }

  /**
   * Applies the requested post-handshake connection behavior to one accepted socket.
   *
   * @param socket accepted TLS socket
   * @throws IOException if the socket cannot be processed
   */
  private void handleAcceptedSocket(SSLSocket socket) throws IOException {
    if (connectionBehavior == ConnectionBehavior.CLOSE_AFTER_HANDSHAKE) {
      return;
    }
    socket.setSoTimeout(500);
    try {
      while (!socket.isClosed()) {
        final int value = socket.getInputStream().read();
        if (value < 0) {
          return;
        }
      }
    } catch (SocketTimeoutException ignored) {
      // The short timeout keeps the connection alive for renegotiation probes without stalling the
      // test suite when no additional TLS records arrive.
    }
  }

  /**
   * Creates a self-signed certificate for the generated test identity.
   *
   * @param keyPair generated key pair
   * @param commonName certificate common name
   * @param validity generated certificate validity window
   * @return generated self-signed certificate
   * @throws Exception if the certificate cannot be created
   */
  private static X509Certificate createCertificate(
      KeyPair keyPair, String commonName, CertificateValidity validity) throws Exception {
    final Instant now = Instant.now();
    final Instant notBefore =
        validity == CertificateValidity.EXPIRED
            ? now.minus(5, ChronoUnit.DAYS)
            : now.minus(1, ChronoUnit.DAYS);
    final Instant notAfter =
        validity == CertificateValidity.EXPIRED
            ? now.minus(1, ChronoUnit.DAYS)
            : now.plus(5, ChronoUnit.DAYS);

    final X500Name subject = new X500Name("CN=" + commonName);
    final JcaX509v3CertificateBuilder certificateBuilder =
        new JcaX509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(notBefore),
            Date.from(notAfter),
            subject,
            keyPair.getPublic());
    final ContentSigner contentSigner =
        new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
    final X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

    return new JcaX509CertificateConverter().getCertificate(certificateHolder);
  }

  /**
   * Closes the server socket, shuts down the accept loop, and deletes the generated identity.
   *
   * @throws Exception if the generated identity cannot be deleted
   */
  @Override
  public void close() throws Exception {
    serverSocket.close();
    executorService.shutdownNow();
    serverIdentity.close();
  }
}
