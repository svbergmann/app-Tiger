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
package de.gematik.test.tiger.glue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.gematik.test.tiger.common.config.TigerConfigurationKey;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.test.tiger.tlstests.TlsConnectionConfiguration;
import de.gematik.test.tiger.tlstests.TlsProbeEvidence;
import de.gematik.test.tiger.tlstests.TlsSessionSummary;
import de.gematik.test.tiger.tlstests.TlsTestCase;
import de.gematik.test.tiger.tlstests.TlsTestProfile;
import de.gematik.test.tiger.tlstests.TlsTestReport;
import de.gematik.test.tiger.tlstests.TlsTestRequest;
import de.gematik.test.tiger.tlstests.TlsTestResult;
import de.gematik.test.tiger.tlstests.TlsTestRunner;
import de.gematik.test.tiger.tlstests.TlsTestTarget;
import de.gematik.test.tiger.tlstests.TlsTestVerdict;
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
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

class TigerTlsTestsGlueTest {

  private final TigerTlsTestsGlue glue = new TigerTlsTestsGlue();
  @TempDir Path tempDir;

  @AfterEach
  void cleanUp() {
    TigerGlobalConfiguration.deleteFromAllSources(new TigerConfigurationKey("tls.report"));
  }

  @Test
  void shouldRunTlsProfileAndAssertResults() throws Exception {
    try (TlsTestServer server = TlsTestServer.start("TLSv1.2")) {
      assertThatNoException()
          .isThrownBy(
              () -> {
                glue.runTlsTestProfile("default", "127.0.0.1", server.port());
                glue.assertOverallTlsVerdict("passed");
                glue.assertTlsTestVerdict("handshake", "passed");
                glue.assertTlsTestDetailMatches("handshake", "Handshake succeeded.*");
                glue.assertTlsTestOpenSslCommandMatches("handshake", ".*openssl s_client.*");
              });
    }
  }

  @Test
  void shouldStoreTlsReportAsLocalVariable() throws Exception {
    try (TlsTestServer server = TlsTestServer.start("TLSv1.2")) {
      glue.runTlsTestProfileAndStoreResult("default", "127.0.0.1", server.port(), "tls.report");

      assertThat(TigerGlobalConfiguration.readStringOptional("tls.report"))
          .hasValueSatisfying(
              json -> {
                assertThat(json).contains("\"profile\" : \"DEFAULT\"");
                assertThat(json).contains("\"verdict\" : \"PASSED\"");
                assertThat(json).contains("reproductionCommands");
              });
    }
  }

  @Test
  void shouldApplyConfiguredTlsExecutionSettings() throws Exception {
    final TlsTestRunner tlsTestRunner = mock(TlsTestRunner.class);
    final TigerTlsTestsGlue configuredGlue = new TigerTlsTestsGlue(tlsTestRunner);
    try (GeneratedIdentity trustStoreIdentity = createIdentity("Tiger TLS Trust");
        GeneratedIdentity clientIdentity = createIdentity("Tiger TLS Client")) {
      when(tlsTestRunner.run(any()))
          .thenReturn(reportFor(new TlsTestTarget("127.0.0.1", 8443, "tls.example.test")));

      configuredGlue.disableTlsTrustAllCertificates();
      configuredGlue.enableTlsHostnameVerification();
      configuredGlue.setTlsTrustStoreIdentity(trustStoreIdentity.compactFormat());
      configuredGlue.setTlsClientIdentity(clientIdentity.compactFormat());
      configuredGlue.setTlsTimeoutInSeconds(7);
      configuredGlue.setTlsSniHostName("tls.example.test");
      configuredGlue.setTlsEnabledProtocols("TLSv1.2, TLSv1.3");
      configuredGlue.setTlsEnabledCipherSuites(
          "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
      configuredGlue.runTlsTestProfile("connectivity", "127.0.0.1", 8443);

      final ArgumentCaptor<TlsTestRequest> requestCaptor =
          ArgumentCaptor.forClass(TlsTestRequest.class);
      verify(tlsTestRunner).run(requestCaptor.capture());

      final TlsTestRequest request = requestCaptor.getValue();
      assertThat(request.target().sniHostName()).isEqualTo("tls.example.test");
      assertThat(request.connectionConfiguration().trustAllCertificates()).isFalse();
      assertThat(request.connectionConfiguration().hostnameVerification()).isTrue();
      assertThat(request.connectionConfiguration().timeout()).isEqualTo(Duration.ofSeconds(7));
      assertThat(request.connectionConfiguration().trustStoreIdentity()).isNotNull();
      assertThat(request.connectionConfiguration().clientIdentity()).isNotNull();
      assertThat(request.connectionConfiguration().enabledProtocols())
          .containsExactly("TLSv1.2", "TLSv1.3");
      assertThat(request.connectionConfiguration().enabledCipherSuites())
          .containsExactly(
              "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    }
  }

  @Test
  void shouldResetConfiguredTlsExecutionSettings() {
    final TlsTestRunner tlsTestRunner = mock(TlsTestRunner.class);
    final TigerTlsTestsGlue configuredGlue = new TigerTlsTestsGlue(tlsTestRunner);
    when(tlsTestRunner.run(any()))
        .thenReturn(reportFor(new TlsTestTarget("127.0.0.1", 8443)));

    configuredGlue.disableTlsTrustAllCertificates();
    configuredGlue.enableTlsHostnameVerification();
    configuredGlue.setTlsTimeoutInSeconds(7);
    configuredGlue.setTlsSniHostName("tls.example.test");
    configuredGlue.setTlsEnabledProtocols("TLSv1.2");
    configuredGlue.setTlsEnabledCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    configuredGlue.resetTlsTestConfiguration();
    configuredGlue.runTlsTestProfile("connectivity", "127.0.0.1", 8443);

    final ArgumentCaptor<TlsTestRequest> requestCaptor = ArgumentCaptor.forClass(TlsTestRequest.class);
    verify(tlsTestRunner).run(requestCaptor.capture());

    final TlsTestRequest request = requestCaptor.getValue();
    assertThat(request.target().sniHostName()).isEqualTo("127.0.0.1");
    assertThat(request.connectionConfiguration().trustAllCertificates()).isTrue();
    assertThat(request.connectionConfiguration().hostnameVerification()).isFalse();
    assertThat(request.connectionConfiguration().trustStoreIdentity()).isNull();
    assertThat(request.connectionConfiguration().clientIdentity()).isNull();
    assertThat(request.connectionConfiguration().timeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(request.connectionConfiguration().enabledProtocols()).isEmpty();
    assertThat(request.connectionConfiguration().enabledCipherSuites()).isEmpty();
  }

  @Test
  void shouldAssertNegotiatedProtocolAndCipherSuite() {
    final TlsTestRunner tlsTestRunner = mock(TlsTestRunner.class);
    final TigerTlsTestsGlue configuredGlue = new TigerTlsTestsGlue(tlsTestRunner);
    when(tlsTestRunner.run(any()))
        .thenReturn(
            new TlsTestReport(
                new TlsTestTarget("127.0.0.1", 8443),
                TlsTestProfile.CONNECTIVITY,
                Instant.now(),
                List.of(
                    new TlsTestResult(
                        TlsTestCase.HANDSHAKE,
                        TlsTestVerdict.PASSED,
                        "Handshake succeeded",
                        new TlsSessionSummary(
                            "TLSv1.2",
                            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                            List.of()),
                        new TlsProbeEvidence(
                            List.of(
                                "openssl s_client -connect '127.0.0.1':8443 -showcerts </dev/null"),
                            List.of(),
                            List.of())))));

    configuredGlue.runTlsTestProfile("connectivity", "127.0.0.1", 8443);
    configuredGlue.assertTlsTestNegotiatedProtocol("handshake", "TLSv1.2");
    configuredGlue.assertTlsTestNegotiatedCipherSuite(
        "handshake", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
  }

  @Test
  void shouldAssertAcceptedAndRejectedTlsProtocols() throws Exception {
    try (TlsTestServer server = TlsTestServer.start("TLSv1.2")) {
      assertThatNoException()
          .isThrownBy(() -> glue.assertTlsProtocolAccepted("127.0.0.1", server.port(), "TLSv1.2"));
      assertThatNoException()
          .isThrownBy(() -> glue.assertTlsProtocolRejected("127.0.0.1", server.port(), "TLSv1.3"));
    }
  }

  @Test
  void shouldAssertAcceptedAndRejectedTlsCipherSuites() throws Exception {
    final String acceptedCipherSuite = determineNegotiatedTls12CipherSuite();
    final String rejectedCipherSuite = selectAlternativeCipherSuite(acceptedCipherSuite);
    try (TlsTestServer server =
        TlsTestServer.start(new String[] {"TLSv1.2"}, new String[] {acceptedCipherSuite})) {
      assertThatNoException()
          .isThrownBy(
              () ->
                  glue.assertTlsCipherSuiteAccepted(
                      "127.0.0.1", server.port(), acceptedCipherSuite));
      assertThatNoException()
          .isThrownBy(
              () ->
                  glue.assertTlsCipherSuiteRejected(
                      "127.0.0.1", server.port(), rejectedCipherSuite));
    }
  }

  private TlsTestReport reportFor(TlsTestTarget target) {
    return new TlsTestReport(
        target,
        TlsTestProfile.CONNECTIVITY,
        Instant.now(),
        List.of(
            new TlsTestResult(
                TlsTestCase.HANDSHAKE,
                TlsTestVerdict.PASSED,
                "Handshake succeeded",
                new TlsSessionSummary("TLSv1.2", "TLS_AES_128_GCM_SHA256", List.of()),
                TlsProbeEvidence.empty())));
  }

  private GeneratedIdentity createIdentity(String commonName) throws Exception {
    final KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);

    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();
    final X509Certificate certificate = createCertificate(keyPair, commonName);
    keyStore.setKeyEntry(
        "entry", keyPair.getPrivate(), TlsTestServer.KEYSTORE_PASSWORD, new Certificate[] {certificate});

    final Path keyStoreFile = Files.createTempFile(tempDir, "tiger-tls-glue-", ".p12");
    try (var outputStream = Files.newOutputStream(keyStoreFile)) {
      keyStore.store(outputStream, TlsTestServer.KEYSTORE_PASSWORD);
    }
    return new GeneratedIdentity(keyStoreFile, keyStoreFile.toAbsolutePath() + ";changeit;p12");
  }

  private String determineNegotiatedTls12CipherSuite() throws Exception {
    final TlsTestRunner runner = new TlsTestRunner();
    try (TlsTestServer server = TlsTestServer.start("TLSv1.2")) {
      final TlsTestReport report =
          runner.run(
              new TlsTestRequest(
                  new TlsTestTarget("127.0.0.1", server.port()),
                  TlsTestProfile.CONNECTIVITY,
                  TlsConnectionConfiguration.defaults().withEnabledProtocols(List.of("TLSv1.2"))));
      return report.findResult(TlsTestCase.HANDSHAKE)
          .orElseThrow()
          .sessionSummary()
          .negotiatedCipherSuite();
    }
  }

  private String selectAlternativeCipherSuite(String excludedCipherSuite) throws Exception {
    final SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, null, null);
    return Arrays.stream(sslContext.getSupportedSSLParameters().getCipherSuites())
        .filter(cipherSuite -> cipherSuite.startsWith("TLS_ECDHE_RSA_"))
        .filter(cipherSuite -> !cipherSuite.contains("_CHACHA20_"))
        .filter(cipherSuite -> !cipherSuite.equals(excludedCipherSuite))
        .findFirst()
        .orElseThrow(
            () ->
                new AssertionError(
                    "Expected at least one alternative supported TLS 1.2 RSA cipher suite"));
  }

  private static X509Certificate createCertificate(KeyPair keyPair, String commonName)
      throws Exception {
    final Instant now = Instant.now();
    final X500Name subject = new X500Name("CN=" + commonName);
    final JcaX509v3CertificateBuilder certificateBuilder =
        new JcaX509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(5, ChronoUnit.DAYS)),
            subject,
            keyPair.getPublic());
    final ContentSigner contentSigner =
        new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
    final X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

    return new JcaX509CertificateConverter().getCertificate(certificateHolder);
  }

  private record GeneratedIdentity(Path keyStoreFile, String compactFormat) implements AutoCloseable {

    @Override
    public void close() throws Exception {
      Files.deleteIfExists(keyStoreFile);
    }
  }

  private static final class TlsTestServer implements AutoCloseable {
    private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();

    private final SSLServerSocket serverSocket;
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    private TlsTestServer(SSLServerSocket serverSocket) {
      this.serverSocket = serverSocket;
    }

    static TlsTestServer start(String... enabledProtocols) throws Exception {
      return start(enabledProtocols, null);
    }

    static TlsTestServer start(String[] enabledProtocols, String[] enabledCipherSuites)
        throws Exception {
      final KeyStore keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(null, null);

      final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      final KeyPair keyPair = keyPairGenerator.generateKeyPair();
      final X509Certificate certificate = createCertificate(keyPair, "Tiger TLS Glue Test Server");
      keyStore.setKeyEntry(
          "server", keyPair.getPrivate(), KEYSTORE_PASSWORD, new Certificate[] {certificate});

      final KeyManagerFactory keyManagerFactory =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD);

      final SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());

      final SSLServerSocket serverSocket =
          (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(0);
      serverSocket.setEnabledProtocols(enabledProtocols);
      if (enabledCipherSuites != null && enabledCipherSuites.length > 0) {
        serverSocket.setEnabledCipherSuites(enabledCipherSuites);
      }

      final TlsTestServer tlsTestServer = new TlsTestServer(serverSocket);
      tlsTestServer.startAcceptLoop();
      return tlsTestServer;
    }

    int port() {
      return serverSocket.getLocalPort();
    }

    private void startAcceptLoop() {
      executorService.submit(
          () -> {
            while (!serverSocket.isClosed()) {
              try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                socket.setUseClientMode(false);
                socket.startHandshake();
              } catch (SocketException e) {
                if (!serverSocket.isClosed()) {
                  throw new IllegalStateException("TLS glue test server accept loop failed", e);
                }
              } catch (Exception e) {
                if (serverSocket.isClosed()) {
                  return;
                }
              }
            }
          });
    }

    @Override
    public void close() throws Exception {
      serverSocket.close();
      executorService.shutdownNow();
    }
  }
}
