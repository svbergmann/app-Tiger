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

import java.time.Instant;
import java.util.List;

/**
 * Captures the result of one server-side TLS observation run where Tiger accepted a client
 * connection.
 *
 * @param bindHost local bind host of the observation server
 * @param port local TCP port of the observation server
 * @param executedAt timestamp of the observation completion
 * @param verdict overall observation verdict
 * @param details human-readable observation details
 * @param sessionSummary negotiated protocol and cipher details when a handshake completed
 * @param negotiatedApplicationProtocol negotiated ALPN application protocol, or {@code null}
 * @param requestedServerNames SNI server names requested by the client
 * @param clientCertificateSubjects client certificate subject DNs presented by the client
 * @param remoteAddress remote client socket address, or {@code null}
 * @param evidence reproducible observation evidence
 */
public record TlsServerObservationReport(
    String bindHost,
    int port,
    Instant executedAt,
    TlsTestVerdict verdict,
    String details,
    TlsSessionSummary sessionSummary,
    String negotiatedApplicationProtocol,
    List<String> requestedServerNames,
    List<String> clientCertificateSubjects,
    String remoteAddress,
    TlsProbeEvidence evidence) {

  /**
   * Creates a validated server-side TLS observation report.
   *
   * @param bindHost local bind host of the observation server
   * @param port local TCP port of the observation server
   * @param executedAt timestamp of the observation completion
   * @param verdict overall observation verdict
   * @param details human-readable observation details
   * @param sessionSummary negotiated protocol and cipher details when a handshake completed
   * @param negotiatedApplicationProtocol negotiated ALPN application protocol, or {@code null}
   * @param requestedServerNames SNI server names requested by the client
   * @param clientCertificateSubjects client certificate subject DNs presented by the client
   * @param remoteAddress remote client socket address, or {@code null}
   * @param evidence reproducible observation evidence
   */
  public TlsServerObservationReport {
    if (bindHost == null || bindHost.isBlank()) {
      throw new IllegalArgumentException("bindHost must not be blank");
    }
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("port must be between 1 and 65535");
    }
    if (executedAt == null) {
      throw new IllegalArgumentException("executedAt must not be null");
    }
    if (verdict == null) {
      throw new IllegalArgumentException("verdict must not be null");
    }
    if (details == null || details.isBlank()) {
      throw new IllegalArgumentException("details must not be blank");
    }
    requestedServerNames =
        List.copyOf(requestedServerNames == null ? List.of() : requestedServerNames);
    clientCertificateSubjects =
        List.copyOf(clientCertificateSubjects == null ? List.of() : clientCertificateSubjects);
    evidence = evidence == null ? TlsProbeEvidence.empty() : evidence;
  }

  /**
   * Returns whether the observation completed with a successful handshake.
   *
   * @return {@code true} if the observation completed successfully
   */
  public boolean successful() {
    return verdict == TlsTestVerdict.PASSED;
  }
}
