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

import java.time.Duration;
import java.time.Instant;
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
          new TlsConnectionConfiguration(false, false, null, null, Duration.ofSeconds(10));

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

  private void assertPassed(TlsTestResult result) {
    assertThat(result.verdict()).isEqualTo(TlsTestVerdict.PASSED);
    assertThat(result.sessionSummary()).isNotNull();
  }
}
