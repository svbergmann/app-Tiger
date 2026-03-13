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
 * Failsafe integration tests for the active TLS compliance runner.
 */
class TlsComplianceRunnerIT {

  private final TlsComplianceRunner complianceRunner = new TlsComplianceRunner();

  /**
   * Verifies protocol scanning and malformed-record rejection in the integration-test phase.
   *
   * @throws Exception if the TLS server fixture cannot be started
   */
  @Test
  void protocolScanAndMalformedRecordProbeShouldWorkInIntegrationPhase() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsFeatureSupportReport scanReport =
          complianceRunner.scanProtocols(
              new TlsTestTarget("127.0.0.1", server.port()),
              List.of("TLSv1.2", "TLSv1.3"),
              TlsConnectionConfiguration.defaults());
      final TlsBehaviorProbeReport malformedRecordReport =
          complianceRunner.probeMalformedTlsRecordRejection(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(scanReport.supportedFeatures()).containsExactly("TLSv1.2");
      assertThat(scanReport.rejectedFeatures()).containsExactly("TLSv1.3");
      assertThat(malformedRecordReport.verdict()).isEqualTo(TlsTestVerdict.PASSED);
    }
  }

  /**
   * Verifies session resumption and OCSP stapling probing in the integration-test phase.
   *
   * @throws Exception if the TLS server fixture cannot be started
   */
  @Test
  void sessionResumptionAndOcspProbeShouldWorkInIntegrationPhase() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsBehaviorProbeReport sessionResumptionReport =
          complianceRunner.probeTls12SessionResumption(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());
      final TlsBehaviorProbeReport ocspStaplingReport =
          complianceRunner.probeOcspStapling(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(sessionResumptionReport.initialSessionSummary()).isNotNull();
      assertThat(sessionResumptionReport.followUpSessionSummary()).isNotNull();
      assertThat(ocspStaplingReport.verdict()).isEqualTo(TlsTestVerdict.FAILED);
    }
  }

  /**
   * Verifies secure-renegotiation probing and unknown-extension tolerance in the integration-test
   * phase.
   *
   * @throws Exception if the TLS server fixture cannot be started
   */
  @Test
  void secureRenegotiationAndUnknownExtensionProbeShouldWorkInIntegrationPhase() throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(TlsTestServer.CertificateValidity.VALID, "TLSv1.2")) {
      final TlsBehaviorProbeReport secureRenegotiationReport =
          complianceRunner.probeTls12SecureRenegotiationSupport(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());
      final TlsBehaviorProbeReport unknownExtensionReport =
          complianceRunner.probeUnknownExtensionTolerance(
              new TlsTestTarget("127.0.0.1", server.port()),
              TlsConnectionConfiguration.defaults());

      assertThat(secureRenegotiationReport.initialSessionSummary()).isNotNull();
      assertThat(unknownExtensionReport.verdict()).isEqualTo(TlsTestVerdict.PASSED);
    }
  }

  /**
   * Verifies named-group and signature-scheme scanning in the integration-test phase.
   *
   * @throws Exception if the TLS server fixture cannot be started
   */
  @Test
  void namedGroupAndSignatureSchemeScanShouldProduceStructuredResultsInIntegrationPhase()
      throws Exception {
    try (TlsTestServer server =
        TlsTestServer.start(
            TlsTestServer.CertificateValidity.VALID,
            new String[] {"TLSv1.2"},
            new String[] {selectSupportedEcdheRsaCipherSuite()})) {
      final TlsFeatureSupportReport namedGroupReport =
          complianceRunner.scanNamedGroups(
              new TlsTestTarget("127.0.0.1", server.port()),
              List.of("x25519", "secp256r1", "ffdhe2048"),
              TlsConnectionConfiguration.defaults().withEnabledProtocols(List.of("TLSv1.2")));
      final TlsFeatureSupportReport signatureSchemeReport =
          complianceRunner.scanSignatureSchemes(
              new TlsTestTarget("127.0.0.1", server.port()),
              List.of("rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp256r1_sha256"),
              TlsConnectionConfiguration.defaults().withEnabledProtocols(List.of("TLSv1.2")));

      assertThat(namedGroupReport.results()).hasSize(3);
      assertThat(namedGroupReport.rejectedFeatures()).contains("ffdhe2048");
      assertThat(namedGroupReport.findResult("x25519"))
          .hasValueSatisfying(
              result ->
                  assertThat(result.evidence().primaryReproductionCommand())
                      .hasValueSatisfying(command -> assertThat(command).contains("-groups")));
      assertThat(signatureSchemeReport.results()).hasSize(3);
      assertThat(signatureSchemeReport.findResult("rsa_pkcs1_sha256"))
          .hasValueSatisfying(
              result ->
                  assertThat(result.evidence().primaryReproductionCommand())
                      .hasValueSatisfying(command -> assertThat(command).contains("-sigalgs")));
      assertThat(signatureSchemeReport.rejectedFeatures()).contains("ecdsa_secp256r1_sha256");
    }
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
}
