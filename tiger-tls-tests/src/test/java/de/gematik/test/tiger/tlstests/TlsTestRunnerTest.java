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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.test.tiger.common.pki.TigerConfigurationPkiIdentity;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;

class TlsTestRunnerTest {

  private final TlsTestRunner runner = new TlsTestRunner();

  @Test
  void defaultProfileShouldPassAgainstTls12Server() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      TlsTestReport report =
          runner.run(
              TlsTestRequest.of(
                  new TlsTestTarget("127.0.0.1", server.port()), TlsTestProfile.DEFAULT));

      assertThat(report.overallVerdict()).isEqualTo(TlsTestVerdict.PASSED);
      assertThat(report.findResult(TlsTestCase.HANDSHAKE)).hasValueSatisfying(this::assertPassed);
      assertThat(report.findResult(TlsTestCase.SUPPORTS_TLS_1_2))
          .hasValueSatisfying(this::assertPassed);
      assertThat(report.findResult(TlsTestCase.PRESENTS_CERTIFICATE))
          .hasValueSatisfying(this::assertPassed);
      assertThat(report.findResult(TlsTestCase.CERTIFICATE_CURRENTLY_VALID))
          .hasValueSatisfying(this::assertPassed);
    }
  }

  @Test
  void strictModernProfileShouldFailAgainstTls12OnlyServer() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      TlsTestReport report =
          runner.run(
              TlsTestRequest.of(
                  new TlsTestTarget("127.0.0.1", server.port()), TlsTestProfile.STRICT_MODERN));

      assertThat(report.overallVerdict()).isEqualTo(TlsTestVerdict.FAILED);
      assertThat(report.findResult(TlsTestCase.SUPPORTS_TLS_1_3))
          .hasValueSatisfying(
              result -> {
                assertThat(result.verdict()).isEqualTo(TlsTestVerdict.FAILED);
                assertThat(result.details()).contains("Handshake failed");
              });
    }
  }

  @Test
  void disablingTrustAllShouldFailAgainstSelfSignedServer() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      TlsConnectionConfiguration connectionConfiguration =
          new TlsConnectionConfiguration(
              false, false, null, null, Duration.ofSeconds(10), List.of(), List.of());

      TlsTestReport report =
          runner.run(
              new TlsTestRequest(
                  new TlsTestTarget("127.0.0.1", server.port()),
                  TlsTestProfile.CONNECTIVITY,
                  connectionConfiguration));

      assertThat(report.overallVerdict()).isEqualTo(TlsTestVerdict.FAILED);
      assertThat(report.findResult(TlsTestCase.HANDSHAKE))
          .hasValueSatisfying(
              result -> {
                assertThat(result.verdict()).isEqualTo(TlsTestVerdict.FAILED);
                assertThat(result.details()).contains("Handshake failed");
              });
    }
  }

  @Test
  void configuredTrustStoreShouldAllowSelfSignedServer() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      TlsConnectionConfiguration connectionConfiguration =
          new TlsConnectionConfiguration(
              false,
              false,
              new TigerConfigurationPkiIdentity(server.serverIdentityString()),
              null,
              Duration.ofSeconds(10),
              List.of(),
              List.of());

      TlsTestReport report =
          runner.run(
              new TlsTestRequest(
                  new TlsTestTarget("127.0.0.1", server.port()),
                  TlsTestProfile.CONNECTIVITY,
                  connectionConfiguration));

      assertThat(report.overallVerdict()).isEqualTo(TlsTestVerdict.PASSED);
      assertThat(report.findResult(TlsTestCase.HANDSHAKE)).hasValueSatisfying(this::assertPassed);
    }
  }

  @Test
  void clientIdentityShouldAllowMutualTlsHandshake() throws Exception {
    try (TlsTestServer.GeneratedIdentity clientIdentity =
            TlsTestServer.createIdentity(
                "Tiger TLS Client", TlsTestServer.CertificateValidity.VALID);
        TlsTestServer server =
            TlsTestServer.startMutualTls(
                TlsTestServer.CertificateValidity.VALID, clientIdentity, "TLSv1.2")) {
      TlsConnectionConfiguration connectionConfiguration =
          new TlsConnectionConfiguration(
              true,
              false,
              null,
              new TigerConfigurationPkiIdentity(clientIdentity.compactFormat()),
              Duration.ofSeconds(10),
              List.of(),
              List.of());

      TlsTestReport report =
          runner.run(
              new TlsTestRequest(
                  new TlsTestTarget("127.0.0.1", server.port()),
                  TlsTestProfile.CONNECTIVITY,
                  connectionConfiguration));

      assertThat(report.overallVerdict()).isEqualTo(TlsTestVerdict.PASSED);
      assertThat(report.findResult(TlsTestCase.HANDSHAKE)).hasValueSatisfying(this::assertPassed);
    }
  }

  @Test
  void expiredCertificatesShouldFailValidityCheck() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.EXPIRED, "TLSv1.2")) {
      TlsTestReport report =
          runner.run(
              TlsTestRequest.of(
                  new TlsTestTarget("127.0.0.1", server.port()), TlsTestProfile.DEFAULT));

      assertThat(report.findResult(TlsTestCase.CERTIFICATE_CURRENTLY_VALID))
          .hasValueSatisfying(
              result -> {
                assertThat(result.verdict()).isEqualTo(TlsTestVerdict.FAILED);
                assertThat(result.details()).contains("Certificate validity check failed");
              });
      assertThat(report.executedAt()).isBeforeOrEqualTo(Instant.now());
    }
  }

  @Test
  void configuredProtocolRestrictionShouldFailAgainstTls12OnlyServer() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      TlsConnectionConfiguration connectionConfiguration =
          TlsConnectionConfiguration.defaults().withEnabledProtocols(List.of("TLSv1.3"));

      TlsTestReport report =
          runner.run(
              new TlsTestRequest(
                  new TlsTestTarget("127.0.0.1", server.port()),
                  TlsTestProfile.CONNECTIVITY,
                  connectionConfiguration));

      assertThat(report.overallVerdict()).isEqualTo(TlsTestVerdict.FAILED);
      assertThat(report.findResult(TlsTestCase.HANDSHAKE))
          .hasValueSatisfying(
              result -> {
                assertThat(result.verdict()).isEqualTo(TlsTestVerdict.FAILED);
                assertThat(result.details()).contains("Handshake failed");
              });
    }
  }

  @Test
  void configuredCipherSuiteShouldHandshakeWhenServerSharesTheSuite() throws Exception {
    final String cipherSuite = determineNegotiatedTls12CipherSuite();
    try (TlsTestServer server =
        TlsTestServer.start(
            TlsTestServer.CertificateValidity.VALID,
            new String[] {"TLSv1.2"},
            new String[] {cipherSuite})) {
      TlsConnectionConfiguration connectionConfiguration =
          TlsConnectionConfiguration.defaults()
              .withEnabledProtocols(List.of("TLSv1.2"))
              .withEnabledCipherSuites(List.of(cipherSuite));

      TlsTestReport report =
          runner.run(
              new TlsTestRequest(
                  new TlsTestTarget("127.0.0.1", server.port()),
                  TlsTestProfile.CONNECTIVITY,
                  connectionConfiguration));

      assertThat(report.overallVerdict()).isEqualTo(TlsTestVerdict.PASSED);
      assertThat(report.findResult(TlsTestCase.HANDSHAKE))
          .hasValueSatisfying(
              result -> {
                assertThat(result.verdict()).isEqualTo(TlsTestVerdict.PASSED);
                assertThat(result.sessionSummary()).isNotNull();
                assertThat(result.sessionSummary().negotiatedCipherSuite()).isEqualTo(cipherSuite);
              });
    }
  }

  @Test
  void configuredCipherSuiteShouldFailWhenServerDoesNotSupportIt() throws Exception {
    final String workingCipherSuite = determineNegotiatedTls12CipherSuite();
    final String unsupportedClientCipherSuite = selectAlternativeCipherSuite(workingCipherSuite);
    try (TlsTestServer server =
        TlsTestServer.start(
            TlsTestServer.CertificateValidity.VALID,
            new String[] {"TLSv1.2"},
            new String[] {workingCipherSuite})) {
      TlsConnectionConfiguration connectionConfiguration =
          TlsConnectionConfiguration.defaults()
              .withEnabledProtocols(List.of("TLSv1.2"))
              .withEnabledCipherSuites(List.of(unsupportedClientCipherSuite));

      TlsTestReport report =
          runner.run(
              new TlsTestRequest(
                  new TlsTestTarget("127.0.0.1", server.port()),
                  TlsTestProfile.CONNECTIVITY,
                  connectionConfiguration));

      assertThat(report.overallVerdict()).isEqualTo(TlsTestVerdict.FAILED);
      assertThat(report.findResult(TlsTestCase.HANDSHAKE))
          .hasValueSatisfying(
              result -> {
                assertThat(result.verdict()).isEqualTo(TlsTestVerdict.FAILED);
                assertThat(result.details()).contains("Handshake failed");
              });
    }
  }

  private void assertPassed(TlsTestResult result) {
    assertThat(result.verdict()).isEqualTo(TlsTestVerdict.PASSED);
    assertThat(result.sessionSummary()).isNotNull();
    assertThat(result.evidence().reproductionCommands()).isNotEmpty();
    assertThat(result.evidence().logEntries()).isNotEmpty();
  }

  private String determineNegotiatedTls12CipherSuite() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
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

  private String selectAlternativeCipherSuite(String excludedCipherSuite)
      throws NoSuchAlgorithmException {
    final SSLContext sslContext = SSLContext.getInstance("TLS");
    try {
      sslContext.init(null, null, null);
    } catch (Exception e) {
      throw new IllegalStateException("Unable to initialize SSLContext for cipher suite discovery", e);
    }
    final List<String> cipherSuites =
        Arrays.stream(sslContext.getSupportedSSLParameters().getCipherSuites())
            .filter(cipherSuite -> cipherSuite.startsWith("TLS_ECDHE_RSA_"))
            .filter(cipherSuite -> !cipherSuite.contains("_CHACHA20_"))
            .filter(cipherSuite -> !cipherSuite.equals(excludedCipherSuite))
            .toList();
    assertThat(cipherSuites)
        .withFailMessage("Expected at least one alternative supported TLS 1.2 RSA cipher suite")
        .isNotEmpty();
    return cipherSuites.getFirst();
  }
}
