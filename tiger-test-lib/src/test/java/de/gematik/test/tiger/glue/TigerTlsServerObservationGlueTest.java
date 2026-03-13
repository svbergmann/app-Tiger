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
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.test.tiger.common.pki.TigerConfigurationPkiIdentity;
import de.gematik.test.tiger.common.pki.TigerPkiIdentity;
import de.gematik.test.tiger.tlstests.TlsComplianceRunner;
import de.gematik.test.tiger.tlstests.TlsProbeEvidence;
import de.gematik.test.tiger.tlstests.TlsServerConnectionConfiguration;
import de.gematik.test.tiger.tlstests.TlsServerObservationHandle;
import de.gematik.test.tiger.tlstests.TlsServerObservationReport;
import de.gematik.test.tiger.tlstests.TlsServerObservationRunner;
import de.gematik.test.tiger.tlstests.TlsSessionSummary;
import de.gematik.test.tiger.tlstests.TlsTestRunner;
import de.gematik.test.tiger.tlstests.TlsTestVerdict;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Tests the TGR glue around the server-side TLS observation runner.
 */
class TigerTlsServerObservationGlueTest {

  private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();

  /**
   * Verifies that a real server observation can capture ALPN and SNI from a local TLS client.
   *
   * @throws Exception if the observation server or local client cannot be started
   */
  @Test
  void shouldRunRealServerObservationAndCaptureAlpnAndSni() throws Exception {
    final TigerTlsTestsGlue glue = new TigerTlsTestsGlue();
    try (GeneratedIdentity serverIdentity = createIdentity("Tiger TLS Observation Server")) {
      glue.resetTlsServerObservationConfiguration();
      glue.setTlsServerIdentity(serverIdentity.compactFormat());
      glue.setTlsServerEnabledProtocols("TLSv1.2");
      glue.setTlsServerApplicationProtocols("h2");
      glue.startTlsServerObservationOnEphemeralPort();
      glue.storeTlsServerObservationPort("tls.server.observation.port");

      final int port =
          Integer.parseInt(
              TigerGlobalConfiguration.readStringOptional("tls.server.observation.port")
                  .orElseThrow());
      connectClient(
          "127.0.0.1",
          port,
          serverIdentity,
          null,
          "dut.example.test",
          new String[] {"TLSv1.2"},
          null,
          new String[] {"h2"});

      assertThatNoException()
          .isThrownBy(
              () -> {
                glue.awaitLastTlsServerObservation();
                glue.assertLastTlsServerObservationVerdict("passed");
                glue.assertLastTlsServerObservationNegotiatedProtocol("TLSv1.2");
                glue.assertLastTlsServerObservationApplicationProtocol("h2");
                glue.assertLastTlsServerObservationContainsSni("dut.example.test");
                glue.assertLastTlsServerObservationRemoteAddressMatches(".+:[0-9]+");
                glue.assertLastTlsServerObservationContainsNoClientCertificate();
                glue.assertLastTlsServerObservationOpenSslCommandMatches(".*openssl s_client.*");
                glue.storeLastTlsServerObservation("tls.server.observation.report");
              });

      assertThat(TigerGlobalConfiguration.readStringOptional("tls.server.observation.report"))
          .hasValueSatisfying(json -> assertThat(json).contains("requestedServerNames"));
    }
  }

  /**
   * Verifies that the glue can assert an observation report without any requested SNI names.
   *
   * @throws Exception if the mocked observation handle cannot be awaited
   */
  @Test
  void shouldAssertServerObservationWithoutSni() throws Exception {
    final TlsTestRunner tlsTestRunner = mock(TlsTestRunner.class);
    final TlsComplianceRunner complianceRunner = mock(TlsComplianceRunner.class);
    final TlsServerObservationRunner observationRunner = mock(TlsServerObservationRunner.class);
    final TlsServerObservationHandle observationHandle = mock(TlsServerObservationHandle.class);
    final TigerTlsTestsGlue glue =
        new TigerTlsTestsGlue(tlsTestRunner, complianceRunner, observationRunner);

    when(observationHandle.port()).thenReturn(9443);
    when(observationHandle.awaitReport())
        .thenReturn(
            new TlsServerObservationReport(
                "127.0.0.1",
                9443,
                Instant.now(),
                TlsTestVerdict.PASSED,
                "Observed one TLS client connection",
                new TlsSessionSummary("TLSv1.2", "TLS_AES_128_GCM_SHA256", List.of()),
                null,
                List.of(),
                List.of(),
                "127.0.0.1:50000",
                new TlsProbeEvidence(
                    List.of("openssl s_client -connect '127.0.0.1':9443 </dev/null"),
                    List.of(),
                    List.of())));
    when(observationRunner.start(anyInt(), argThat(configuration -> configuration != null)))
        .thenReturn(observationHandle);

    glue.startTlsServerObservation(0);
    glue.awaitLastTlsServerObservation();
    glue.assertLastTlsServerObservationVerdict("passed");
    glue.assertLastTlsServerObservationContainsNoSni();
  }

  /**
   * Verifies that a real mutual-TLS observation captures the presented client certificate.
   *
   * @throws Exception if the observation server or local client cannot be started
   */
  @Test
  void shouldRunRealMutualTlsServerObservation() throws Exception {
    final TigerTlsTestsGlue glue = new TigerTlsTestsGlue();
    try (GeneratedIdentity serverIdentity = createIdentity("Tiger TLS Observation Server");
        GeneratedIdentity clientIdentity = createIdentity("Tiger TLS Observation Client")) {
      glue.resetTlsServerObservationConfiguration();
      glue.setTlsServerIdentity(serverIdentity.compactFormat());
      glue.setTlsServerTrustIdentity(clientIdentity.compactFormat());
      glue.enableTlsServerClientCertificateRequirement();
      glue.setTlsServerEnabledProtocols("TLSv1.2");
      glue.startTlsServerObservationOnEphemeralPort();

      final int port = gluePort(glue);
      connectClient(
          "127.0.0.1",
          port,
          serverIdentity,
          clientIdentity,
          "dut.example.test",
          new String[] {"TLSv1.2"},
          null,
          null);

      glue.awaitLastTlsServerObservation();
      glue.assertLastTlsServerObservationVerdict("passed");
      glue.assertLastTlsServerObservationContainsClientCertificate();
      glue.assertLastTlsServerObservationClientCertificateSubjectMatches(".*Tiger TLS Observation Client.*");
    }
  }

  /**
   * Verifies that server-observation configuration is forwarded to the runner.
   *
   * @throws Exception if the mocked observation handle cannot be awaited
   */
  @Test
  void shouldForwardServerObservationConfigurationToRunner() throws Exception {
    final TlsTestRunner tlsTestRunner = mock(TlsTestRunner.class);
    final TlsComplianceRunner complianceRunner = mock(TlsComplianceRunner.class);
    final TlsServerObservationRunner observationRunner = mock(TlsServerObservationRunner.class);
    final TlsServerObservationHandle observationHandle = mock(TlsServerObservationHandle.class);
    final TigerTlsTestsGlue glue =
        new TigerTlsTestsGlue(tlsTestRunner, complianceRunner, observationRunner);

    try (GeneratedIdentity serverIdentity = createIdentity("Tiger TLS Observation Server");
        GeneratedIdentity clientIdentity = createIdentity("Tiger TLS Observation Client")) {
      when(observationHandle.port()).thenReturn(9443);
      when(observationHandle.awaitReport())
          .thenReturn(
              new TlsServerObservationReport(
                  "127.0.0.1",
                  9443,
                  Instant.now(),
                  TlsTestVerdict.PASSED,
                  "Observed one TLS client connection",
                  new TlsSessionSummary("TLSv1.2", "TLS_AES_128_GCM_SHA256", List.of()),
                  "h2",
                  List.of("dut.example.test"),
                  List.of(),
                  "127.0.0.1:50000",
                  new TlsProbeEvidence(
                      List.of("openssl s_client -connect '127.0.0.1':9443 </dev/null"),
                      List.of(),
                      List.of())));
      when(observationRunner.start(anyInt(), argThat(configuration -> configuration != null)))
          .thenReturn(observationHandle);

      glue.setTlsServerIdentity(serverIdentity.compactFormat());
      glue.setTlsServerTrustIdentity(clientIdentity.compactFormat());
      glue.enableTlsServerClientCertificateRequirement();
      glue.setTlsServerBindHost("127.0.0.1");
      glue.setTlsServerTimeoutInSeconds(7);
      glue.setTlsServerEnabledProtocols("TLSv1.2");
      glue.setTlsServerEnabledCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
      glue.setTlsServerApplicationProtocols("h2, http/1.1");
      glue.startTlsServerObservation(0);
      glue.awaitLastTlsServerObservation();
    }

    final ArgumentCaptor<TlsServerConnectionConfiguration> configurationCaptor =
        ArgumentCaptor.forClass(TlsServerConnectionConfiguration.class);
    verify(observationRunner).start(anyInt(), configurationCaptor.capture());

    final TlsServerConnectionConfiguration configuration = configurationCaptor.getValue();
    assertThat(configuration.bindHost()).isEqualTo("127.0.0.1");
    assertThat(configuration.timeout()).isEqualTo(Duration.ofSeconds(7));
    assertThat(configuration.requireClientCertificate()).isTrue();
    assertThat(configuration.serverIdentity()).isNotNull();
    assertThat(configuration.trustedClientIdentity()).isNotNull();
    assertThat(configuration.enabledProtocols()).containsExactly("TLSv1.2");
    assertThat(configuration.enabledCipherSuites())
        .containsExactly("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    assertThat(configuration.applicationProtocols()).containsExactly("h2", "http/1.1");
  }

  /**
   * Returns the bound port of the running observation server through the public glue surface.
   *
   * @param glue glue instance under test
   * @return bound observation-server port
   */
  private int gluePort(TigerTlsTestsGlue glue) {
    glue.storeTlsServerObservationPort("tls.server.observation.port");
    return Integer.parseInt(
        TigerGlobalConfiguration.readStringOptional("tls.server.observation.port").orElseThrow());
  }

  /**
   * Connects a real local TLS client to the running observation server.
   *
   * @param host observation-server host
   * @param port observation-server port
   * @param trustedServerIdentity trust anchor used by the local client
   * @param clientIdentity optional client certificate identity
   * @param sniHostName requested SNI host name
   * @param enabledProtocols optional client protocol restrictions
   * @param enabledCipherSuites optional client cipher-suite restrictions
   * @param applicationProtocols optional client ALPN application protocols
   * @throws Exception if the client handshake fails
   */
  private void connectClient(
      String host,
      int port,
      GeneratedIdentity trustedServerIdentity,
      GeneratedIdentity clientIdentity,
      String sniHostName,
      String[] enabledProtocols,
      String[] enabledCipherSuites,
      String[] applicationProtocols)
      throws Exception {
    final SSLContext sslContext =
        buildClientSslContext(
            trustedServerIdentity,
            clientIdentity == null ? null : new TigerConfigurationPkiIdentity(clientIdentity.compactFormat()));
    try (SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port)) {
      final SSLParameters sslParameters = socket.getSSLParameters();
      if (enabledProtocols != null) {
        sslParameters.setProtocols(enabledProtocols);
      }
      if (enabledCipherSuites != null) {
        sslParameters.setCipherSuites(enabledCipherSuites);
      }
    if (applicationProtocols != null) {
      sslParameters.setApplicationProtocols(applicationProtocols);
    }
      if (sniHostName != null && !sniHostName.isBlank()) {
        sslParameters.setServerNames(List.of(new SNIHostName(sniHostName)));
      }
      socket.setSSLParameters(sslParameters);
      socket.startHandshake();
    }
  }

  /**
   * Builds the client-side SSL context used by the local observation test client.
   *
   * @param trustedServerIdentity trust anchor used by the local client
   * @param clientIdentity optional client certificate identity
   * @return initialized client-side SSL context
   * @throws Exception if the SSL context cannot be initialized
   */
  private SSLContext buildClientSslContext(
      GeneratedIdentity trustedServerIdentity, TigerConfigurationPkiIdentity clientIdentity)
      throws Exception {
    final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("trusted", trustedServerIdentity.certificate());
    final TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);

    final SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(
        buildClientKeyManagers(clientIdentity),
        trustManagerFactory.getTrustManagers(),
        new SecureRandom());
    return sslContext;
  }

  /**
   * Builds client key managers for an optional client certificate identity.
   *
   * @param clientIdentity optional client certificate identity
   * @return initialized client key managers, or {@code null}
   * @throws Exception if the client key material cannot be initialized
   */
  private javax.net.ssl.KeyManager[] buildClientKeyManagers(
      TigerConfigurationPkiIdentity clientIdentity) throws Exception {
    if (clientIdentity == null) {
      return null;
    }
    final TigerPkiIdentity identity =
        new TigerPkiIdentity(clientIdentity.getFileLoadingInformation());
    final KeyStore keyStore = identity.toKeyStoreWithPassword("changeit");
    final KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, "changeit".toCharArray());
    return keyManagerFactory.getKeyManagers();
  }

  /**
   * Creates a reusable PKCS#12 identity used by the local observation tests.
   *
   * @param commonName certificate common name
   * @return reusable PKCS#12 identity
   * @throws Exception if the identity cannot be created
   */
  private GeneratedIdentity createIdentity(String commonName) throws Exception {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();
    final X509Certificate certificate = createCertificate(keyPair, commonName);

    final KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);
    keyStore.setKeyEntry(
        "entry", keyPair.getPrivate(), KEYSTORE_PASSWORD, new Certificate[] {certificate});

    final Path keyStoreFile = Files.createTempFile("tiger-tls-observation-", ".p12");
    try (var outputStream = Files.newOutputStream(keyStoreFile)) {
      keyStore.store(outputStream, KEYSTORE_PASSWORD);
    }

    return new GeneratedIdentity(
        keyStoreFile, keyStoreFile.toAbsolutePath() + ";changeit;p12", certificate);
  }

  /**
   * Creates a self-signed certificate for one local observation test identity.
   *
   * @param keyPair generated RSA key pair
   * @param commonName certificate common name
   * @return generated certificate
   * @throws Exception if the certificate cannot be created
   */
  private X509Certificate createCertificate(KeyPair keyPair, String commonName) throws Exception {
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

  /**
   * Local reusable PKCS#12 identity used by the glue tests.
   *
   * @param keyStoreFile generated PKCS#12 file
   * @param compactFormat Tiger compact identity token
   * @param certificate generated certificate
   */
  private record GeneratedIdentity(Path keyStoreFile, String compactFormat, X509Certificate certificate)
      implements AutoCloseable {

    /**
     * Deletes the generated PKCS#12 file.
     *
     * @throws Exception if the temporary file cannot be deleted
     */
    @Override
    public void close() throws Exception {
      Files.deleteIfExists(keyStoreFile);
    }
  }
}
