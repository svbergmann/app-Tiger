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
import java.util.Optional;

/**
 * Aggregates the results of probing a set of TLS protocols or cipher suites against one target.
 *
 * @param target scanned target endpoint
 * @param featureType feature family represented by this scan
 * @param executedAt timestamp of the scan execution
 * @param results ordered per-feature scan results
 */
public record TlsFeatureSupportReport(
    TlsTestTarget target,
    TlsScannedFeatureType featureType,
    Instant executedAt,
    List<TlsFeatureSupportResult> results) {

  /**
   * Creates an immutable feature scan report.
   *
   * @param target scanned target endpoint
   * @param featureType feature family represented by this scan
   * @param executedAt timestamp of the scan execution
   * @param results ordered per-feature scan results
   */
  public TlsFeatureSupportReport {
    if (target == null) {
      throw new IllegalArgumentException("target must not be null");
    }
    if (featureType == null) {
      throw new IllegalArgumentException("featureType must not be null");
    }
    if (executedAt == null) {
      throw new IllegalArgumentException("executedAt must not be null");
    }
    results = List.copyOf(results == null ? List.of() : results);
  }

  /**
   * Searches the scan result for one feature token.
   *
   * @param feature scanned feature token to resolve
   * @return matching result if present
   */
  public Optional<TlsFeatureSupportResult> findResult(String feature) {
    if (feature == null || feature.isBlank()) {
      throw new IllegalArgumentException("feature must not be blank");
    }
    return results.stream().filter(result -> result.feature().equals(feature)).findFirst();
  }

  /**
   * Returns all feature tokens accepted by the target.
   *
   * @return ordered list of accepted feature tokens
   */
  public List<String> supportedFeatures() {
    return results.stream()
        .filter(result -> result.verdict() == TlsTestVerdict.PASSED)
        .map(TlsFeatureSupportResult::feature)
        .toList();
  }

  /**
   * Returns all feature tokens rejected by the target.
   *
   * @return ordered list of rejected feature tokens
   */
  public List<String> rejectedFeatures() {
    return results.stream()
        .filter(result -> result.verdict() == TlsTestVerdict.FAILED)
        .map(TlsFeatureSupportResult::feature)
        .toList();
  }
}
