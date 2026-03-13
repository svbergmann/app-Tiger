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
 * Captures the result of one active TLS behavior probe against a target endpoint.
 *
 * @param target probed target endpoint
 * @param probeType executed behavior probe type
 * @param executedAt timestamp of the probe execution
 * @param verdict outcome of the behavior probe
 * @param details human-readable execution details
 * @param initialSessionSummary negotiated session summary of the first handshake
 * @param followUpSessionSummary negotiated session summary of the follow-up handshake when present
 * @param evidence reproducible execution evidence for the probe
 */
public record TlsBehaviorProbeReport(
    TlsTestTarget target,
    TlsBehaviorProbeType probeType,
    Instant executedAt,
    TlsTestVerdict verdict,
    String details,
    TlsSessionSummary initialSessionSummary,
    TlsSessionSummary followUpSessionSummary,
    TlsProbeEvidence evidence) {

  /**
   * Creates a validated behavior probe report.
   *
   * @param target probed target endpoint
   * @param probeType executed behavior probe type
   * @param executedAt timestamp of the probe execution
   * @param verdict outcome of the behavior probe
   * @param details human-readable execution details
   * @param initialSessionSummary negotiated session summary of the first handshake
   * @param followUpSessionSummary negotiated session summary of the follow-up handshake when present
   * @param evidence reproducible execution evidence for the probe
   */
  public TlsBehaviorProbeReport {
    if (target == null) {
      throw new IllegalArgumentException("target must not be null");
    }
    if (probeType == null) {
      throw new IllegalArgumentException("probeType must not be null");
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
    evidence = evidence == null ? TlsProbeEvidence.empty() : evidence;
  }

  /**
   * Returns whether the probed behavior was supported.
   *
   * @return {@code true} if the behavior probe passed
   */
  public boolean successful() {
    return verdict == TlsTestVerdict.PASSED;
  }
}
