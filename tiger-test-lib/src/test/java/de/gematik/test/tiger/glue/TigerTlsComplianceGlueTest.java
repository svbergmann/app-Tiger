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

import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.test.tiger.tlstests.TlsBehaviorProbeReport;
import de.gematik.test.tiger.tlstests.TlsBehaviorProbeType;
import de.gematik.test.tiger.tlstests.TlsComplianceRunner;
import de.gematik.test.tiger.tlstests.TlsConnectionConfiguration;
import de.gematik.test.tiger.tlstests.TlsFeatureSupportReport;
import de.gematik.test.tiger.tlstests.TlsFeatureSupportResult;
import de.gematik.test.tiger.tlstests.TlsProbeEvidence;
import de.gematik.test.tiger.tlstests.TlsScannedFeatureType;
import de.gematik.test.tiger.tlstests.TlsTestRunner;
import de.gematik.test.tiger.tlstests.TlsTestTarget;
import de.gematik.test.tiger.tlstests.TlsTestVerdict;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Tests the TGR glue around the active TLS compliance runner.
 */
class TigerTlsComplianceGlueTest {

  /**
   * Verifies that the real protocol-scan glue can distinguish accepted and rejected protocol
   * versions against a local TLS 1.2 server.
   *
   * @throws Exception if the test server cannot be started
   */
  @Test
  void shouldRunRealProtocolScanAgainstTls12Server() throws Exception {
    final TigerTlsTestsGlue glue = new TigerTlsTestsGlue();
    try (TlsTestServer server = TlsTestServer.start("TLSv1.2")) {
      assertThatNoException()
          .isThrownBy(
              () -> {
                glue.runTlsProtocolScan("TLSv1.2, TLSv1.3", "127.0.0.1", server.port());
                glue.assertLastTlsProtocolScanAccepts("TLSv1.2");
                glue.assertLastTlsProtocolScanRejects("TLSv1.3");
                glue.assertLastTlsProtocolScanAcceptedProtocols("TLSv1.2");
                glue.assertTlsProtocolScanOpenSslCommandMatches("TLSv1.2", ".*-tls1_2.*");
                glue.storeLastTlsProtocolScan("tls.protocol.scan");
              });
      assertThat(TigerGlobalConfiguration.readStringOptional("tls.protocol.scan"))
          .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
    }
  }

  /**
   * Verifies that the real named-group and signature-scheme glue can scan a local TLS 1.2 server.
   *
   * @throws Exception if the test server cannot be started
   */
  @Test
  void shouldRunRealNamedGroupAndSignatureSchemeScansAgainstTls12Server() throws Exception {
    final TigerTlsTestsGlue glue = new TigerTlsTestsGlue();
    try (TlsTestServer server = TlsTestServer.start("TLSv1.2")) {
      assertThatNoException()
          .isThrownBy(
              () -> {
                glue.runTlsNamedGroupScan("x25519, secp256r1, ffdhe2048", "127.0.0.1", server.port());
                glue.assertTlsNamedGroupScanOpenSslCommandMatches("x25519", ".*-groups.*");
                glue.storeLastTlsNamedGroupScan("tls.named.group.scan");
                glue.runTlsSignatureSchemeScan(
                    "rsa_pss_rsae_sha256, rsa_pkcs1_sha256, ecdsa_secp256r1_sha256",
                    "127.0.0.1",
                    server.port());
                glue.assertTlsSignatureSchemeScanOpenSslCommandMatches(
                    "rsa_pkcs1_sha256", ".*-sigalgs.*");
                glue.storeLastTlsSignatureSchemeScan("tls.signature.scheme.scan");
              });
      assertThat(TigerGlobalConfiguration.readStringOptional("tls.named.group.scan"))
          .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
      assertThat(TigerGlobalConfiguration.readStringOptional("tls.signature.scheme.scan"))
          .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
    }
  }

  /**
   * Verifies that the real ALPN application-protocol glue can scan a local TLS 1.2 server.
   *
   * @throws Exception if the test server cannot be started
   */
  @Test
  void shouldRunRealApplicationProtocolScanAgainstTls12Server() throws Exception {
    final TigerTlsTestsGlue glue = new TigerTlsTestsGlue();
    try (TlsTestServer server =
        TlsTestServer.start(new String[] {"TLSv1.2"}, null, new String[] {"h2"})) {
      assertThatNoException()
          .isThrownBy(
              () -> {
                glue.runTlsApplicationProtocolScan("h2, http/1.1", "127.0.0.1", server.port());
                glue.assertLastTlsApplicationProtocolScanAccepts("h2");
                glue.assertLastTlsApplicationProtocolScanRejects("http/1.1");
                glue.assertLastTlsApplicationProtocolScanAcceptedProtocols("h2");
                glue.assertTlsApplicationProtocolScanOpenSslCommandMatches("h2", ".*-alpn 'h2'.*");
                glue.storeLastTlsApplicationProtocolScan("tls.application.protocol.scan");
              });
      assertThat(TigerGlobalConfiguration.readStringOptional("tls.application.protocol.scan"))
          .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
    }
  }

  /**
   * Verifies that the real malformed-record and OCSP stapling glue steps work against the local
   * TLS server.
   *
   * @throws Exception if the test server cannot be started
   */
  @Test
  void shouldRunRealBehaviorProbesAgainstTls12Server() throws Exception {
    final TigerTlsTestsGlue glue = new TigerTlsTestsGlue();
    try (TlsTestServer server = TlsTestServer.start("TLSv1.2")) {
      assertThatNoException()
          .isThrownBy(
              () -> {
                glue.assertMalformedTlsRecordsRejected("127.0.0.1", server.port());
                glue.assertTlsOcspStaplingNotSupported("127.0.0.1", server.port());
                glue.assertTls12SecureRenegotiationSupported("127.0.0.1", server.port());
                glue.assertLastTlsBehaviorProbeOpenSslCommandMatches(".*-tlsextdebug.*");
                glue.assertTls12ExtendedMasterSecretSupported("127.0.0.1", server.port());
                glue.assertTlsUnknownExtensionsTolerated("127.0.0.1", server.port());
                glue.storeLastTlsBehaviorProbe("tls.behavior.probe");
              });
      assertThat(TigerGlobalConfiguration.readStringOptional("tls.behavior.probe"))
          .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
    }
  }

  /**
   * Verifies that the real encrypt-then-mac glue steps produce structured output on a TLS 1.2 CBC
   * server.
   *
   * @throws Exception if the test server cannot be started
   */
  @Test
  void shouldRunRealEncryptThenMacProbeAgainstTls12CbcServer() throws Exception {
    final TigerTlsTestsGlue glue = new TigerTlsTestsGlue();
    try (TlsTestServer server =
        TlsTestServer.start(
            new String[] {"TLSv1.2"},
            new String[] {TlsTestServer.selectSupportedTls12CbcCipherSuite()},
            null)) {
      assertThatNoException()
          .isThrownBy(
              () -> {
                glue.runTls12EncryptThenMacProbe("127.0.0.1", server.port());
                glue.assertLastTlsBehaviorProbeDetailMatches(".*encrypt-then-mac.*");
                glue.assertLastTlsBehaviorProbeOpenSslCommandMatches(".*openssl ciphers.*");
              });
    }
  }

  /**
   * Verifies that reusable TLS execution settings are forwarded to the compliance runner.
   */
  @Test
  void shouldApplyConfiguredTlsExecutionSettingsToComplianceRunner() {
    final TlsTestRunner tlsTestRunner = mock(TlsTestRunner.class);
    final TlsComplianceRunner complianceRunner = mock(TlsComplianceRunner.class);
    final TigerTlsTestsGlue glue = new TigerTlsTestsGlue(tlsTestRunner, complianceRunner);

    when(complianceRunner.scanProtocols(any(), any(), any()))
        .thenReturn(
            new TlsFeatureSupportReport(
                new TlsTestTarget("127.0.0.1", 8443, "tls.example.test"),
                TlsScannedFeatureType.PROTOCOL,
                Instant.now(),
                List.of(
                    new TlsFeatureSupportResult(
                        "TLSv1.2", TlsTestVerdict.PASSED, "Handshake succeeded", null, null))));
    when(complianceRunner.scanNamedGroups(any(), any(), any()))
        .thenReturn(
            new TlsFeatureSupportReport(
                new TlsTestTarget("127.0.0.1", 8443, "tls.example.test"),
                TlsScannedFeatureType.NAMED_GROUP,
                Instant.now(),
                List.of(
                    new TlsFeatureSupportResult(
                        "x25519", TlsTestVerdict.PASSED, "Handshake succeeded", null, null))));
    when(complianceRunner.scanApplicationProtocols(any(), any(), any()))
        .thenReturn(
            new TlsFeatureSupportReport(
                new TlsTestTarget("127.0.0.1", 8443, "tls.example.test"),
                TlsScannedFeatureType.APPLICATION_PROTOCOL,
                Instant.now(),
                List.of(
                    new TlsFeatureSupportResult(
                        "h2", TlsTestVerdict.PASSED, "ALPN selected h2", null, null))));
    when(complianceRunner.scanSignatureSchemes(any(), any(), any()))
        .thenReturn(
            new TlsFeatureSupportReport(
                new TlsTestTarget("127.0.0.1", 8443, "tls.example.test"),
                TlsScannedFeatureType.SIGNATURE_SCHEME,
                Instant.now(),
                List.of(
                    new TlsFeatureSupportResult(
                        "rsa_pkcs1_sha256",
                        TlsTestVerdict.PASSED,
                        "Handshake succeeded",
                        null,
                        null))));
    when(complianceRunner.probeTls12SessionResumption(any(), any()))
        .thenReturn(
            new TlsBehaviorProbeReport(
                new TlsTestTarget("127.0.0.1", 8443, "tls.example.test"),
                TlsBehaviorProbeType.TLS_1_2_SESSION_RESUMPTION,
                Instant.now(),
                TlsTestVerdict.PASSED,
                "TLS 1.2 session resumption succeeded",
                null,
                null,
                null));
    when(complianceRunner.probeOcspStapling(any(), any()))
        .thenReturn(
            new TlsBehaviorProbeReport(
                new TlsTestTarget("127.0.0.1", 8443, "tls.example.test"),
                TlsBehaviorProbeType.OCSP_STAPLING,
                Instant.now(),
                TlsTestVerdict.FAILED,
                "Peer did not return a stapled OCSP response",
                null,
                null,
                null));
    when(complianceRunner.probeTls12EncryptThenMacSupport(any(), any()))
        .thenReturn(
            new TlsBehaviorProbeReport(
                new TlsTestTarget("127.0.0.1", 8443, "tls.example.test"),
                TlsBehaviorProbeType.TLS_1_2_ENCRYPT_THEN_MAC,
                Instant.now(),
                TlsTestVerdict.PASSED,
                "Peer negotiated encrypt-then-mac during a TLS 1.2 CBC handshake",
                null,
                null,
                null));

    glue.disableTlsTrustAllCertificates();
    glue.enableTlsHostnameVerification();
    glue.setTlsTimeoutInSeconds(7);
    glue.setTlsSniHostName("tls.example.test");
    glue.runTlsProtocolScan("TLSv1.2, TLSv1.3", "127.0.0.1", 8443);
    glue.runTlsNamedGroupScan("x25519", "127.0.0.1", 8443);
    glue.runTlsApplicationProtocolScan("h2", "127.0.0.1", 8443);
    glue.runTlsSignatureSchemeScan("rsa_pkcs1_sha256", "127.0.0.1", 8443);
    glue.runTls12SessionResumptionProbe("127.0.0.1", 8443);
    glue.runTlsOcspStaplingProbe("127.0.0.1", 8443);
    glue.runTls12EncryptThenMacProbe("127.0.0.1", 8443);

    final ArgumentCaptor<TlsTestTarget> targetCaptor = ArgumentCaptor.forClass(TlsTestTarget.class);
    final ArgumentCaptor<List<String>> protocolsCaptor = ArgumentCaptor.forClass(List.class);
    final ArgumentCaptor<TlsConnectionConfiguration> configurationCaptor =
        ArgumentCaptor.forClass(TlsConnectionConfiguration.class);
    verify(complianceRunner)
        .scanProtocols(targetCaptor.capture(), protocolsCaptor.capture(), configurationCaptor.capture());
    verify(complianceRunner).scanNamedGroups(any(), any(), configurationCaptor.capture());
    verify(complianceRunner).scanApplicationProtocols(any(), any(), configurationCaptor.capture());
    verify(complianceRunner).scanSignatureSchemes(any(), any(), configurationCaptor.capture());
    verify(complianceRunner).probeTls12SessionResumption(any(), configurationCaptor.capture());
    verify(complianceRunner).probeOcspStapling(any(), configurationCaptor.capture());
    verify(complianceRunner).probeTls12EncryptThenMacSupport(any(), configurationCaptor.capture());

    assertThat(targetCaptor.getValue().sniHostName()).isEqualTo("tls.example.test");
    assertThat(protocolsCaptor.getValue()).containsExactly("TLSv1.2", "TLSv1.3");
    assertThat(configurationCaptor.getAllValues())
        .allSatisfy(
            configuration -> {
              assertThat(configuration.trustAllCertificates()).isFalse();
              assertThat(configuration.hostnameVerification()).isTrue();
              assertThat(configuration.timeout()).isEqualTo(Duration.ofSeconds(7));
            });
  }

  /**
   * Verifies the assertion surface for protocol scans, cipher-suite scans, and TLS behavior probes.
   */
  @Test
  void shouldAssertComplianceReports() {
    final TlsTestRunner tlsTestRunner = mock(TlsTestRunner.class);
    final TlsComplianceRunner complianceRunner = mock(TlsComplianceRunner.class);
    final TigerTlsTestsGlue glue = new TigerTlsTestsGlue(tlsTestRunner, complianceRunner);

    when(complianceRunner.scanProtocols(any(), any(), any()))
        .thenReturn(
            new TlsFeatureSupportReport(
                new TlsTestTarget("127.0.0.1", 8443),
                TlsScannedFeatureType.PROTOCOL,
                Instant.now(),
                List.of(
                    new TlsFeatureSupportResult(
                        "TLSv1.2",
                        TlsTestVerdict.PASSED,
                        "Handshake succeeded",
                        null,
                        new TlsProbeEvidence(
                            List.of("openssl s_client -connect '127.0.0.1':8443 -tls1_2 </dev/null"),
                            List.of(),
                            List.of())),
                    new TlsFeatureSupportResult(
                        "TLSv1.3",
                        TlsTestVerdict.FAILED,
                        "Handshake failed",
                        null,
                        new TlsProbeEvidence(
                            List.of("openssl s_client -connect '127.0.0.1':8443 -tls1_3 </dev/null"),
                            List.of(),
                            List.of())))));
    when(complianceRunner.scanCipherSuites(any(), any(), any()))
        .thenReturn(
            new TlsFeatureSupportReport(
                new TlsTestTarget("127.0.0.1", 8443),
                TlsScannedFeatureType.CIPHER_SUITE,
                Instant.now(),
                List.of(
                    new TlsFeatureSupportResult(
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                        TlsTestVerdict.PASSED,
                        "Handshake succeeded",
                        null,
                        new TlsProbeEvidence(
                            List.of("openssl ciphers -stdname | grep -F 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'"),
                            List.of(),
                            List.of())),
                    new TlsFeatureSupportResult(
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        TlsTestVerdict.FAILED,
                        "Handshake failed",
                        null,
                        new TlsProbeEvidence(
                            List.of("openssl ciphers -stdname | grep -F 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'"),
                            List.of(),
                            List.of())))));
    when(complianceRunner.scanNamedGroups(any(), any(), any()))
        .thenReturn(
            new TlsFeatureSupportReport(
                new TlsTestTarget("127.0.0.1", 8443),
                TlsScannedFeatureType.NAMED_GROUP,
                Instant.now(),
                List.of(
                    new TlsFeatureSupportResult(
                        "x25519",
                        TlsTestVerdict.PASSED,
                        "Handshake succeeded",
                        null,
                        new TlsProbeEvidence(
                            List.of("openssl s_client -connect '127.0.0.1':8443 -groups 'x25519' </dev/null"),
                            List.of(),
                            List.of())),
                    new TlsFeatureSupportResult(
                        "ffdhe2048",
                        TlsTestVerdict.FAILED,
                        "Handshake failed",
                        null,
                        new TlsProbeEvidence(
                            List.of("openssl s_client -connect '127.0.0.1':8443 -groups 'ffdhe2048' </dev/null"),
                            List.of(),
                            List.of())))));
    when(complianceRunner.scanApplicationProtocols(any(), any(), any()))
        .thenReturn(
            new TlsFeatureSupportReport(
                new TlsTestTarget("127.0.0.1", 8443),
                TlsScannedFeatureType.APPLICATION_PROTOCOL,
                Instant.now(),
                List.of(
                    new TlsFeatureSupportResult(
                        "h2",
                        TlsTestVerdict.PASSED,
                        "ALPN selected h2",
                        null,
                        new TlsProbeEvidence(
                            List.of("openssl s_client -connect '127.0.0.1':8443 -alpn 'h2' </dev/null"),
                            List.of(),
                            List.of())),
                    new TlsFeatureSupportResult(
                        "http/1.1",
                        TlsTestVerdict.FAILED,
                        "No ALPN application protocol selected",
                        null,
                        new TlsProbeEvidence(
                            List.of("openssl s_client -connect '127.0.0.1':8443 -alpn 'http/1.1' </dev/null"),
                            List.of(),
                            List.of())))));
    when(complianceRunner.scanSignatureSchemes(any(), any(), any()))
        .thenReturn(
            new TlsFeatureSupportReport(
                new TlsTestTarget("127.0.0.1", 8443),
                TlsScannedFeatureType.SIGNATURE_SCHEME,
                Instant.now(),
                List.of(
                    new TlsFeatureSupportResult(
                        "rsa_pkcs1_sha256",
                        TlsTestVerdict.PASSED,
                        "Handshake succeeded",
                        null,
                        new TlsProbeEvidence(
                            List.of("openssl s_client -connect '127.0.0.1':8443 -sigalgs 'rsa_pkcs1_sha256' </dev/null"),
                            List.of(),
                            List.of())),
                    new TlsFeatureSupportResult(
                        "ecdsa_secp256r1_sha256",
                        TlsTestVerdict.FAILED,
                        "Handshake failed",
                        null,
                        new TlsProbeEvidence(
                            List.of("openssl s_client -connect '127.0.0.1':8443 -sigalgs 'ecdsa_secp256r1_sha256' </dev/null"),
                            List.of(),
                            List.of())))));
    when(complianceRunner.probeTls12Renegotiation(any(), any()))
        .thenReturn(
            new TlsBehaviorProbeReport(
                new TlsTestTarget("127.0.0.1", 8443),
                TlsBehaviorProbeType.TLS_1_2_RENEGOTIATION,
                Instant.now(),
                TlsTestVerdict.FAILED,
                "TLS 1.2 renegotiation failed: protocol_version",
                null,
                null,
                new TlsProbeEvidence(
                    List.of("printf 'R\\nQ\\n' | openssl s_client -connect '127.0.0.1':8443 -tls1_2"),
                    List.of(),
                    List.of())));
    when(complianceRunner.probeMalformedTlsRecordRejection(any(), any()))
        .thenReturn(
            new TlsBehaviorProbeReport(
                new TlsTestTarget("127.0.0.1", 8443),
                TlsBehaviorProbeType.MALFORMED_TLS_RECORD_REJECTION,
                Instant.now(),
                TlsTestVerdict.PASSED,
                "Peer rejected the malformed TLS record by closing the connection",
                null,
                null,
                new TlsProbeEvidence(List.of(), List.of("No OpenSSL malformed-record mode"), List.of())));
    when(complianceRunner.probeOcspStapling(any(), any()))
        .thenReturn(
            new TlsBehaviorProbeReport(
                new TlsTestTarget("127.0.0.1", 8443),
                TlsBehaviorProbeType.OCSP_STAPLING,
                Instant.now(),
                TlsTestVerdict.FAILED,
                "Peer did not return a stapled OCSP response",
                null,
                null,
                new TlsProbeEvidence(
                    List.of("openssl s_client -connect '127.0.0.1':8443 -status </dev/null"),
                    List.of(),
                    List.of())));
    when(complianceRunner.probeTls12EncryptThenMacSupport(any(), any()))
        .thenReturn(
            new TlsBehaviorProbeReport(
                new TlsTestTarget("127.0.0.1", 8443),
                TlsBehaviorProbeType.TLS_1_2_ENCRYPT_THEN_MAC,
                Instant.now(),
                TlsTestVerdict.PASSED,
                "Peer negotiated encrypt-then-mac during a TLS 1.2 CBC handshake",
                null,
                null,
                new TlsProbeEvidence(
                    List.of(
                        "openssl ciphers -stdname | grep -E 'TLS_(ECDHE|DHE|RSA)_(RSA|ECDSA)?_?WITH_AES_(128|256)_CBC_SHA(256)?'",
                        "openssl s_client -connect '127.0.0.1':8443 -tls1_2 -cipher '<OPENSSL_TLS12_CBC_CIPHER_NAME>' -tlsextdebug </dev/null"),
                    List.of(),
                    List.of())));

    glue.runTlsProtocolScan("TLSv1.2, TLSv1.3", "127.0.0.1", 8443);
    glue.assertLastTlsProtocolScanAccepts("TLSv1.2");
    glue.assertLastTlsProtocolScanRejects("TLSv1.3");
    glue.assertLastTlsProtocolScanAcceptedProtocols("TLSv1.2");
    glue.assertTlsProtocolScanOpenSslCommandMatches("TLSv1.2", ".*-tls1_2.*");
    glue.storeLastTlsProtocolScan("tls.protocol.scan.mock");

    glue.runTlsCipherSuiteScan(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "127.0.0.1",
        8443);
    glue.assertLastTlsCipherSuiteScanAccepts("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    glue.assertLastTlsCipherSuiteScanRejects("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    glue.assertLastTlsCipherSuiteScanAcceptedCipherSuites(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    glue.assertTlsCipherSuiteScanOpenSslCommandMatches(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ".*openssl ciphers.*");
    glue.storeLastTlsCipherSuiteScan("tls.cipher.scan.mock");

    glue.runTlsNamedGroupScan("x25519, ffdhe2048", "127.0.0.1", 8443);
    glue.assertLastTlsNamedGroupScanAccepts("x25519");
    glue.assertLastTlsNamedGroupScanRejects("ffdhe2048");
    glue.assertTlsNamedGroupScanOpenSslCommandMatches("x25519", ".*-groups.*");
    glue.assertTlsNamedGroupAccepted("127.0.0.1", 8443, "x25519");
    glue.assertTlsNamedGroupRejected("127.0.0.1", 8443, "ffdhe2048");
    glue.storeLastTlsNamedGroupScan("tls.named.group.scan.mock");

    glue.runTlsApplicationProtocolScan("h2, http/1.1", "127.0.0.1", 8443);
    glue.assertLastTlsApplicationProtocolScanAccepts("h2");
    glue.assertLastTlsApplicationProtocolScanRejects("http/1.1");
    glue.assertLastTlsApplicationProtocolScanAcceptedProtocols("h2");
    glue.assertTlsApplicationProtocolScanOpenSslCommandMatches("h2", ".*-alpn 'h2'.*");
    glue.assertTlsApplicationProtocolAccepted("127.0.0.1", 8443, "h2");
    glue.assertTlsApplicationProtocolRejected("127.0.0.1", 8443, "http/1.1");
    glue.storeLastTlsApplicationProtocolScan("tls.application.protocol.scan.mock");

    glue.runTlsSignatureSchemeScan(
        "rsa_pkcs1_sha256, ecdsa_secp256r1_sha256", "127.0.0.1", 8443);
    glue.assertLastTlsSignatureSchemeScanAccepts("rsa_pkcs1_sha256");
    glue.assertLastTlsSignatureSchemeScanRejects("ecdsa_secp256r1_sha256");
    glue.assertTlsSignatureSchemeScanOpenSslCommandMatches("rsa_pkcs1_sha256", ".*-sigalgs.*");
    glue.assertTlsSignatureSchemeAccepted("127.0.0.1", 8443, "rsa_pkcs1_sha256");
    glue.assertTlsSignatureSchemeRejected("127.0.0.1", 8443, "ecdsa_secp256r1_sha256");
    glue.storeLastTlsSignatureSchemeScan("tls.signature.scheme.scan.mock");

    glue.runTls12RenegotiationProbe("127.0.0.1", 8443);
    glue.assertLastTlsBehaviorProbeVerdict("failed");
    glue.assertLastTlsBehaviorProbeDetailMatches(".*protocol_version.*");
    glue.assertLastTlsBehaviorProbeOpenSslCommandMatches(".*openssl s_client.*");
    glue.assertTls12RenegotiationRejected("127.0.0.1", 8443);

    glue.runTlsMalformedRecordProbe("127.0.0.1", 8443);
    glue.assertLastTlsBehaviorProbeVerdict("passed");
    glue.assertMalformedTlsRecordsRejected("127.0.0.1", 8443);

    glue.runTlsOcspStaplingProbe("127.0.0.1", 8443);
    glue.assertLastTlsBehaviorProbeVerdict("failed");
    glue.assertTlsOcspStaplingNotSupported("127.0.0.1", 8443);

    glue.runTls12EncryptThenMacProbe("127.0.0.1", 8443);
    glue.assertLastTlsBehaviorProbeVerdict("passed");
    glue.assertTls12EncryptThenMacSupported("127.0.0.1", 8443);
    glue.storeLastTlsBehaviorProbe("tls.behavior.mock");

    assertThat(TigerGlobalConfiguration.readStringOptional("tls.protocol.scan.mock"))
        .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
    assertThat(TigerGlobalConfiguration.readStringOptional("tls.cipher.scan.mock"))
        .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
    assertThat(TigerGlobalConfiguration.readStringOptional("tls.named.group.scan.mock"))
        .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
    assertThat(TigerGlobalConfiguration.readStringOptional("tls.application.protocol.scan.mock"))
        .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
    assertThat(TigerGlobalConfiguration.readStringOptional("tls.signature.scheme.scan.mock"))
        .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
    assertThat(TigerGlobalConfiguration.readStringOptional("tls.behavior.mock"))
        .hasValueSatisfying(json -> assertThat(json).contains("reproductionCommands"));
  }

  /**
   * Minimal in-process TLS server fixture for glue integration tests.
   */
  private static final class TlsTestServer implements AutoCloseable {

    private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();

    private final SSLServerSocket serverSocket;
    private final String[] applicationProtocols;
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    /**
     * Creates a TLS test server fixture.
     *
     * @param serverSocket bound server socket
     * @param applicationProtocols configured ALPN application protocols
     */
    private TlsTestServer(SSLServerSocket serverSocket, String[] applicationProtocols) {
      this.serverSocket = serverSocket;
      this.applicationProtocols =
          applicationProtocols == null ? null : applicationProtocols.clone();
    }

    /**
     * Starts the TLS test server with the requested enabled protocols.
     *
     * @param enabledProtocols enabled server protocols
     * @return started TLS test server
     * @throws Exception if the server cannot be created
     */
    static TlsTestServer start(String... enabledProtocols) throws Exception {
      return start(enabledProtocols, null, null);
    }

    /**
     * Starts the TLS test server with the requested enabled protocols, cipher suites, and ALPN
     * application protocols.
     *
     * @param enabledProtocols enabled server protocols
     * @param enabledCipherSuites enabled server cipher suites
     * @param applicationProtocols enabled ALPN application protocols
     * @return started TLS test server
     * @throws Exception if the server cannot be created
     */
    static TlsTestServer start(
        String[] enabledProtocols, String[] enabledCipherSuites, String[] applicationProtocols)
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
      if (applicationProtocols != null && applicationProtocols.length > 0) {
        final SSLParameters sslParameters = serverSocket.getSSLParameters();
        sslParameters.setApplicationProtocols(applicationProtocols.clone());
        serverSocket.setSSLParameters(sslParameters);
      }

      final TlsTestServer tlsTestServer = new TlsTestServer(serverSocket, applicationProtocols);
      tlsTestServer.startAcceptLoop();
      return tlsTestServer;
    }

    /**
     * Returns the bound server port.
     *
     * @return bound TCP port
     */
    int port() {
      return serverSocket.getLocalPort();
    }

    /**
     * Starts the asynchronous accept loop.
     */
    private void startAcceptLoop() {
      executorService.submit(
          () -> {
            while (!serverSocket.isClosed()) {
              try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                socket.setUseClientMode(false);
                applySocketConfiguration(socket);
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

    /**
     * Applies per-socket TLS settings before the handshake starts.
     *
     * @param socket accepted TLS socket
     */
    private void applySocketConfiguration(SSLSocket socket) {
      if (applicationProtocols == null || applicationProtocols.length == 0) {
        return;
      }
      final SSLParameters sslParameters = socket.getSSLParameters();
      sslParameters.setApplicationProtocols(applicationProtocols.clone());
      socket.setSSLParameters(sslParameters);
    }

    /**
     * Creates a self-signed certificate for the local test server.
     *
     * @param keyPair generated RSA key pair
     * @param commonName certificate common name
     * @return generated certificate
     * @throws Exception if the certificate cannot be created
     */
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

    /**
     * Selects one supported TLS 1.2 CBC cipher suite for encrypt-then-mac glue tests.
     *
     * @return supported TLS 1.2 CBC cipher suite
     * @throws Exception if the TLS SSL context cannot be initialized
     */
    private static String selectSupportedTls12CbcCipherSuite() throws Exception {
      final SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, null, null);
      return java.util.Arrays.stream(sslContext.getSupportedSSLParameters().getCipherSuites())
          .filter(cipherSuite -> cipherSuite.startsWith("TLS_"))
          .filter(cipherSuite -> cipherSuite.contains("_CBC_"))
          .findFirst()
          .orElseThrow(
              () -> new AssertionError("Expected at least one supported TLS 1.2 CBC cipher suite"));
    }

    /**
     * Closes the server socket and stops the accept loop.
     *
     * @throws Exception if the socket cannot be closed
     */
    @Override
    public void close() throws Exception {
      serverSocket.close();
      executorService.shutdownNow();
    }
  }
}
