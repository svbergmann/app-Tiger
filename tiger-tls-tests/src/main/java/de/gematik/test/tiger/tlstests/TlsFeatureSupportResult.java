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

import java.util.List;

/**
 * Captures the outcome of probing one TLS feature token such as a protocol version or cipher
 * suite.
 *
 * @param feature the scanned feature token
 * @param verdict outcome of probing the feature
 * @param details human-readable execution details
 * @param sessionSummary negotiated session summary when the probe succeeded
 * @param evidence reproducible execution evidence for the probe
 */
public record TlsFeatureSupportResult(
    String feature,
    TlsTestVerdict verdict,
    String details,
    TlsSessionSummary sessionSummary,
    TlsProbeEvidence evidence) {

  /**
   * Creates a validated feature probe result.
   *
   * @param feature the scanned feature token
   * @param verdict outcome of probing the feature
   * @param details human-readable execution details
   * @param sessionSummary negotiated session summary when the probe succeeded
   * @param evidence reproducible execution evidence for the probe
   */
  public TlsFeatureSupportResult {
    if (feature == null || feature.isBlank()) {
      throw new IllegalArgumentException("feature must not be blank");
    }
    if (verdict == null) {
      throw new IllegalArgumentException("verdict must not be null");
    }
    if (details == null || details.isBlank()) {
      throw new IllegalArgumentException("details must not be blank");
    }
    evidence = evidence == null ? TlsProbeEvidence.empty() : evidence;
  }
}
