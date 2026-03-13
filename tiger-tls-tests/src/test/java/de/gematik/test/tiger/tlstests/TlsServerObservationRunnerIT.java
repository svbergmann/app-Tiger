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
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Failsafe integration tests for the server-side TLS observation runner.
 */
class TlsServerObservationRunnerIT {

  private final TlsServerObservationRunner observationRunner = new TlsServerObservationRunner();
  private final TlsObservationClient tlsObservationClient = new TlsObservationClient();

  /**
   * Verifies that a successful observation captures ALPN and SNI during the integration-test phase.
   *
   * @throws Exception if the observation server cannot be started
   */
  @Test
  void shouldCaptureAlpnAndSniInIntegrationPhase() throws Exception {
    try (TlsTestServer.GeneratedIdentity serverIdentity =
            TlsTestServer.createIdentity(
                "Tiger TLS Observation Server", TlsTestServer.CertificateValidity.VALID);
        TlsServerObservationHandle handle =
            observationRunner.start(
                0,
                TlsServerConnectionConfiguration.defaults()
                    .withServerIdentity(
                        new TigerConfigurationPkiIdentity(serverIdentity.compactFormat()))
                    .withEnabledProtocols(List.of("TLSv1.2"))
                    .withApplicationProtocols(List.of("h2")))) {
      tlsObservationClient.connect(
          handle.bindHost(),
          handle.port(),
          new TigerConfigurationPkiIdentity(serverIdentity.compactFormat()),
          null,
          "dut.example.test",
          new String[] {"TLSv1.2"},
          null,
          new String[] {"h2"});

      final TlsServerObservationReport report = handle.awaitReport();

      assertThat(report.verdict()).isEqualTo(TlsTestVerdict.PASSED);
      assertThat(report.negotiatedApplicationProtocol()).isEqualTo("h2");
      assertThat(report.requestedServerNames()).contains("dut.example.test");
    }
  }

  /**
   * Verifies that successful mutual TLS observations capture the presented client certificate in
   * the integration-test phase.
   *
   * @throws Exception if the observation server cannot be started
   */
  @Test
  void shouldCaptureMutualTlsClientCertificateInIntegrationPhase() throws Exception {
    try (TlsTestServer.GeneratedIdentity serverIdentity =
            TlsTestServer.createIdentity(
                "Tiger TLS Observation Server", TlsTestServer.CertificateValidity.VALID);
        TlsTestServer.GeneratedIdentity clientIdentity =
            TlsTestServer.createIdentity(
                "Tiger TLS Observation Client", TlsTestServer.CertificateValidity.VALID);
        TlsServerObservationHandle handle =
            observationRunner.start(
                0,
                TlsServerConnectionConfiguration.defaults()
                    .withServerIdentity(
                        new TigerConfigurationPkiIdentity(serverIdentity.compactFormat()))
                    .withTrustedClientIdentity(
                        new TigerConfigurationPkiIdentity(clientIdentity.compactFormat()))
                    .withRequireClientCertificate(true)
                    .withEnabledProtocols(List.of("TLSv1.2")))) {
      tlsObservationClient.connect(
          handle.bindHost(),
          handle.port(),
          new TigerConfigurationPkiIdentity(serverIdentity.compactFormat()),
          new TigerConfigurationPkiIdentity(clientIdentity.compactFormat()),
          "dut.example.test",
          new String[] {"TLSv1.2"},
          null,
          null);

      final TlsServerObservationReport report = handle.awaitReport();

      assertThat(report.verdict()).isEqualTo(TlsTestVerdict.PASSED);
      assertThat(report.clientCertificateSubjects())
          .anyMatch(subject -> subject.contains("CN=Tiger TLS Observation Client"));
    }
  }
}
