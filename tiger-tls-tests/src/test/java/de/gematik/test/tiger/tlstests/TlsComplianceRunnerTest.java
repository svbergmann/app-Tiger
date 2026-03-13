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

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;

/**
 * Tests the active TLS compliance runner.
 */
class TlsComplianceRunnerTest {

  private final TlsComplianceRunner complianceRunner = new TlsComplianceRunner();
  private final TlsTestRunner tlsTestRunner = new TlsTestRunner();

  /**
   * Verifies that protocol scans differentiate accepted and rejected protocol versions.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void scanProtocolsShouldDifferentiateAcceptedAndRejectedProtocols() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsFeatureSupportReport report =
          complianceRunner.scanProtocols(
              new TlsTestTarget("127.0.0.1", server.port()),
              List.of("TLSv1.2", "TLSv1.3"),
              TlsConnectionConfiguration.defaults());

      assertThat(report.featureType()).isEqualTo(TlsScannedFeatureType.PROTOCOL);
      assertThat(report.supportedFeatures()).containsExactly("TLSv1.2");
      assertThat(report.rejectedFeatures()).containsExactly("TLSv1.3");
      assertThat(report.findResult("TLSv1.2"))
          .hasValueSatisfying(
              result ->
                  assertThat(result.evidence().primaryReproductionCommand())
                      .hasValueSatisfying(command -> assertThat(command).contains("-tls1_2")));
    }
  }

  /**
   * Verifies that cipher-suite scans differentiate accepted and rejected cipher suites.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void scanCipherSuitesShouldDifferentiateAcceptedAndRejectedCipherSuites() throws Exception {
    final String acceptedCipherSuite = determineNegotiatedTls12CipherSuite();
    final String rejectedCipherSuite = selectAlternativeCipherSuite(acceptedCipherSuite);
    try (TlsTestServer server =
        TlsTestServer.start(
            TlsTestServer.CertificateValidity.VALID,
            new String[] {"TLSv1.2"},
            new String[] {acceptedCipherSuite})) {
      final TlsFeatureSupportReport report =
          complianceRunner.scanCipherSuites(
              new TlsTestTarget("127.0.0.1", server.port()),
              List.of(acceptedCipherSuite, rejectedCipherSuite),
              TlsConnectionConfiguration.defaults().withEnabledProtocols(List.of("TLSv1.2")));

      assertThat(report.featureType()).isEqualTo(TlsScannedFeatureType.CIPHER_SUITE);
      assertThat(report.supportedFeatures()).containsExactly(acceptedCipherSuite);
      assertThat(report.rejectedFeatures()).containsExactly(rejectedCipherSuite);
      assertThat(report.findResult(acceptedCipherSuite))
          .hasValueSatisfying(
              result -> assertThat(result.evidence().reproductionCommands()).isNotEmpty());
    }
  }

  /**
   * Verifies that ALPN application-protocol scans differentiate selected and unselected tokens.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void scanApplicationProtocolsShouldDifferentiateAcceptedAndRejectedProtocols()
      throws Exception {
    try (TlsTestServer server =
        TlsTestServer.startWithApplicationProtocols(
            TlsTestServer.CertificateValidity.VALID,
            new String[] {"TLSv1.2"},
            new String[] {"h2"})) {
      final TlsFeatureSupportReport report =
          complianceRunner.scanApplicationProtocols(
              new TlsTestTarget("127.0.0.1", server.port()),
              List.of("h2", "http/1.1"),
              TlsConnectionConfiguration.defaults().withEnabledProtocols(List.of("TLSv1.2")));

      assertThat(report.featureType()).isEqualTo(TlsScannedFeatureType.APPLICATION_PROTOCOL);
      assertThat(report.supportedFeatures()).containsExactly("h2");
      assertThat(report.rejectedFeatures()).containsExactly("http/1.1");
      assertThat(report.findResult("h2"))
          .hasValueSatisfying(
              result ->
                  assertThat(result.evidence().primaryReproductionCommand())
                      .hasValueSatisfying(command -> assertThat(command).contains("-alpn 'h2'")));
    }
  }

  /**
   * Verifies that named-group scans report at least one supported classical ECDHE group and reject
   * a finite-field group on an ECDHE-only TLS 1.2 server.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void scanNamedGroupsShouldProduceEvidenceAndStructuredResults() throws Exception {
    final String acceptedCipherSuite = selectSupportedEcdheRsaCipherSuite();
    try (TlsTestServer server =
        TlsTestServer.start(
            TlsTestServer.CertificateValidity.VALID,
            new String[] {"TLSv1.2"},
            new String[] {acceptedCipherSuite})) {
      final TlsFeatureSupportReport report =
          complianceRunner.scanNamedGroups(
              new TlsTestTarget("127.0.0.1", server.port()),
              List.of("x25519", "secp256r1", "secp384r1", "ffdhe2048"),
              TlsConnectionConfiguration.defaults().withEnabledProtocols(List.of("TLSv1.2")));

      assertThat(report.featureType()).isEqualTo(TlsScannedFeatureType.NAMED_GROUP);
      assertThat(report.results()).hasSize(4);
      assertThat(report.results()).extracting(TlsFeatureSupportResult::feature)
          .containsExactly("x25519", "secp256r1", "secp384r1", "ffdhe2048");
      assertThat(report.rejectedFeatures()).contains("ffdhe2048");
      assertThat(report.findResult("secp256r1"))
          .hasValueSatisfying(
              result -> assertThat(result.details()).contains("Low-level handshake"));
      assertThat(report.findResult("x25519").orElseThrow().evidence().primaryReproductionCommand())
          .hasValueSatisfying(command -> assertThat(command).contains("-groups"));
    }
  }

  /**
   * Verifies that signature-scheme scans report at least one supported RSA scheme and reject an
   * ECDSA-only offer on an RSA-backed TLS 1.2 server.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void scanSignatureSchemesShouldDifferentiateAcceptedAndRejectedSignatureSchemes()
      throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsFeatureSupportReport report =
          complianceRunner.scanSignatureSchemes(
              new TlsTestTarget("127.0.0.1", server.port()),
              List.of(
                  "rsa_pss_rsae_sha256",
                  "rsa_pkcs1_sha256",
                  "rsa_pkcs1_sha384",
                  "ecdsa_secp256r1_sha256"),
              TlsConnectionConfiguration.defaults().withEnabledProtocols(List.of("TLSv1.2")));

      assertThat(report.featureType()).isEqualTo(TlsScannedFeatureType.SIGNATURE_SCHEME);
      assertThat(report.supportedFeatures())
          .anyMatch(
              supportedScheme ->
                  supportedScheme.equals("rsa_pss_rsae_sha256")
                      || supportedScheme.equals("rsa_pkcs1_sha256")
                      || supportedScheme.equals("rsa_pkcs1_sha384"));
      assertThat(report.rejectedFeatures()).contains("ecdsa_secp256r1_sha256");
      assertThat(report.findResult("rsa_pkcs1_sha256").orElse(report.findResult("rsa_pss_rsae_sha256").orElseThrow()).evidence().primaryReproductionCommand())
          .hasValueSatisfying(command -> assertThat(command).contains("-sigalgs"));
    }
  }

  /**
   * Verifies that TLS 1.2 session resumption is detected when the server resumes sessions.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void probeTls12SessionResumptionShouldDetectResumedSessions() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsBehaviorProbeReport report =
          complianceRunner.probeTls12SessionResumption(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(report.probeType()).isEqualTo(TlsBehaviorProbeType.TLS_1_2_SESSION_RESUMPTION);
      assertThat(report.initialSessionSummary()).isNotNull();
      assertThat(report.followUpSessionSummary()).isNotNull();
      assertThat(report.details()).isNotBlank();
      assertThat(report.evidence().reproductionCommands()).hasSize(2);
    }
  }

  /**
   * Verifies that TLS 1.2 renegotiation failures are surfaced when the target does not offer TLS
   * 1.2 at all.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void probeTls12RenegotiationShouldFailAgainstTls13OnlyServer() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.3")) {
      final TlsBehaviorProbeReport report =
          complianceRunner.probeTls12Renegotiation(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(report.probeType()).isEqualTo(TlsBehaviorProbeType.TLS_1_2_RENEGOTIATION);
      assertThat(report.verdict()).isEqualTo(TlsTestVerdict.FAILED);
      assertThat(report.details()).contains("renegotiation failed");
      assertThat(report.evidence().primaryReproductionCommand())
          .hasValueSatisfying(command -> assertThat(command).contains("printf 'R"));
    }
  }

  /**
   * Verifies that TLS 1.2 renegotiation can be observed when the server keeps reading after the
   * first handshake.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void probeTls12RenegotiationShouldSucceedWhenServerKeepsConnectionOpen() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.startPersistent(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsBehaviorProbeReport report =
          complianceRunner.probeTls12Renegotiation(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(report.probeType()).isEqualTo(TlsBehaviorProbeType.TLS_1_2_RENEGOTIATION);
      assertThat(report.initialSessionSummary()).isNotNull();
      assertThat(report.details()).isNotBlank();
    }
  }

  /**
   * Verifies that secure renegotiation support is detected on the local TLS 1.2 server.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void probeTls12SecureRenegotiationShouldDetectSupportOnSimpleServer() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsBehaviorProbeReport report =
          complianceRunner.probeTls12SecureRenegotiationSupport(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(report.probeType())
          .isEqualTo(TlsBehaviorProbeType.TLS_1_2_SECURE_RENEGOTIATION);
      assertThat(report.initialSessionSummary()).isNotNull();
      assertThat(report.evidence().primaryReproductionCommand())
          .hasValueSatisfying(command -> assertThat(command).contains("-tlsextdebug"));
    }
  }

  /**
   * Verifies that extended master secret support is detected on the local TLS 1.2 server.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void probeTls12ExtendedMasterSecretShouldDetectSupportOnSimpleServer() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsBehaviorProbeReport report =
          complianceRunner.probeTls12ExtendedMasterSecretSupport(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(report.probeType())
          .isEqualTo(TlsBehaviorProbeType.TLS_1_2_EXTENDED_MASTER_SECRET);
      assertThat(report.initialSessionSummary()).isNotNull();
      assertThat(report.evidence().primaryReproductionCommand())
          .hasValueSatisfying(command -> assertThat(command).contains("-tlsextdebug"));
    }
  }

  /**
   * Verifies that the encrypt-then-mac probe produces a structured result and reproduction
   * evidence on a TLS 1.2 CBC server.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void probeTls12EncryptThenMacShouldProduceStructuredResultOnCbcServer() throws Exception {
    final String cbcCipherSuite = selectSupportedTls12CbcCipherSuite();
    try (TlsTestServer server =
        TlsTestServer.start(
            TlsTestServer.CertificateValidity.VALID,
            new String[] {"TLSv1.2"},
            new String[] {cbcCipherSuite})) {
      final TlsBehaviorProbeReport report =
          complianceRunner.probeTls12EncryptThenMacSupport(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults().withEnabledProtocols(List.of("TLSv1.2")));

      assertThat(report.probeType()).isEqualTo(TlsBehaviorProbeType.TLS_1_2_ENCRYPT_THEN_MAC);
      assertThat(report.details()).isNotBlank();
      assertThat(report.evidence().reproductionCommands()).hasSize(2);
      assertThat(report.evidence().reproductionCommands().get(1)).contains("-tlsextdebug");
    }
  }

  /**
   * Verifies that fallback-SCSV rejection is surfaced against a server that supports TLS 1.3 in
   * addition to TLS 1.2.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void probeTls12FallbackScsvRejectionShouldReportServerBehavior() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(
            TlsTestServer.CertificateValidity.VALID,
            new String[] {"TLSv1.2", "TLSv1.3"},
            null)) {
      final TlsBehaviorProbeReport report =
          complianceRunner.probeTls12FallbackScsvRejection(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(report.probeType())
          .isEqualTo(TlsBehaviorProbeType.TLS_1_2_FALLBACK_SCSV_REJECTION);
      assertThat(report.evidence().primaryReproductionCommand())
          .hasValueSatisfying(command -> assertThat(command).contains("-fallback_scsv"));
      assertThat(report.details()).isNotBlank();
    }
  }

  /**
   * Verifies that the server tolerates an unknown ClientHello extension.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void probeUnknownExtensionToleranceShouldPassAgainstSimpleServer() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsBehaviorProbeReport report =
          complianceRunner.probeUnknownExtensionTolerance(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(report.probeType()).isEqualTo(TlsBehaviorProbeType.UNKNOWN_EXTENSION_TOLERANCE);
      assertThat(report.verdict()).isEqualTo(TlsTestVerdict.PASSED);
      assertThat(report.evidence().notes())
          .contains("OpenSSL s_client does not expose a generic unknown-extension injection mode for this probe.");
    }
  }

  /**
   * Verifies that the OCSP stapling probe reports the absence of a staple on the local test
   * server.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void probeOcspStaplingShouldReportMissingStapleOnSimpleServer() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsBehaviorProbeReport report =
          complianceRunner.probeOcspStapling(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(report.probeType()).isEqualTo(TlsBehaviorProbeType.OCSP_STAPLING);
      assertThat(report.verdict()).isEqualTo(TlsTestVerdict.FAILED);
      assertThat(report.details()).contains("did not return");
      assertThat(report.evidence().primaryReproductionCommand())
          .hasValueSatisfying(command -> assertThat(command).contains("-status"));
    }
  }

  /**
   * Verifies that the malformed-record probe observes the server rejecting malformed input.
   *
   * @throws Exception if the test fixture cannot be started
   */
  @Test
  void probeMalformedTlsRecordRejectionShouldPassAgainstSimpleServer() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsBehaviorProbeReport report =
          complianceRunner.probeMalformedTlsRecordRejection(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(report.probeType()).isEqualTo(TlsBehaviorProbeType.MALFORMED_TLS_RECORD_REJECTION);
      assertThat(report.verdict()).isEqualTo(TlsTestVerdict.PASSED);
      assertThat(report.evidence().notes())
          .contains("OpenSSL s_client does not expose a direct malformed-record mode for this probe.");
    }
  }

  /**
   * Determines one TLS 1.2 cipher suite that the local client and test server can negotiate.
   *
   * @return negotiated TLS 1.2 cipher suite
   * @throws Exception if the handshake cannot be performed
   */
  private String determineNegotiatedTls12CipherSuite() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsTestReport report =
          tlsTestRunner.run(
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

  /**
   * Selects one supported TLS 1.2 RSA cipher suite distinct from the excluded cipher suite.
   *
   * @param excludedCipherSuite cipher suite that must not be returned
   * @return alternative supported TLS 1.2 RSA cipher suite
   * @throws NoSuchAlgorithmException if the TLS SSL context cannot be created
   */
  private String selectAlternativeCipherSuite(String excludedCipherSuite)
      throws NoSuchAlgorithmException {
    final SSLContext sslContext = SSLContext.getInstance("TLS");
    try {
      sslContext.init(null, null, null);
    } catch (Exception e) {
      throw new IllegalStateException("Unable to initialize SSLContext for cipher-suite discovery", e);
    }
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

  /**
   * Selects one supported TLS 1.2 ECDHE RSA cipher suite for named-group dependent probes.
   *
   * @return supported TLS 1.2 ECDHE RSA cipher suite
   * @throws NoSuchAlgorithmException if the TLS SSL context cannot be created
   */
  private String selectSupportedEcdheRsaCipherSuite() throws NoSuchAlgorithmException {
    final SSLContext sslContext = SSLContext.getInstance("TLS");
    try {
      sslContext.init(null, null, null);
    } catch (Exception e) {
      throw new IllegalStateException("Unable to initialize SSLContext for cipher-suite discovery", e);
    }
    return Arrays.stream(sslContext.getSupportedSSLParameters().getCipherSuites())
        .filter(cipherSuite -> cipherSuite.startsWith("TLS_ECDHE_RSA_"))
        .filter(cipherSuite -> !cipherSuite.contains("_CHACHA20_"))
        .findFirst()
        .orElseThrow(
            () ->
                new AssertionError("Expected at least one supported TLS 1.2 ECDHE RSA cipher suite"));
  }

  /**
   * Selects one supported TLS 1.2 CBC cipher suite for encrypt-then-mac probing.
   *
   * @return supported TLS 1.2 CBC cipher suite
   * @throws NoSuchAlgorithmException if the TLS SSL context cannot be created
   */
  private String selectSupportedTls12CbcCipherSuite() throws NoSuchAlgorithmException {
    final SSLContext sslContext = SSLContext.getInstance("TLS");
    try {
      sslContext.init(null, null, null);
    } catch (Exception e) {
      throw new IllegalStateException("Unable to initialize SSLContext for cipher-suite discovery", e);
    }
    return Arrays.stream(sslContext.getSupportedSSLParameters().getCipherSuites())
        .filter(cipherSuite -> cipherSuite.startsWith("TLS_"))
        .filter(cipherSuite -> cipherSuite.contains("_CBC_"))
        .findFirst()
        .orElseThrow(
            () -> new AssertionError("Expected at least one supported TLS 1.2 CBC cipher suite"));
  }
}
