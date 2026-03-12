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
 * Captures the result of a TLS test run against one target.
 *
 * @param target the tested target
 * @param profile the executed profile
 * @param executedAt timestamp of the test execution
 * @param results the individual test case results
 */
public record TlsTestReport(
    TlsTestTarget target, TlsTestProfile profile, Instant executedAt, List<TlsTestResult> results) {

  /**
   * Creates an immutable test report.
   *
   * @param target the tested target
   * @param profile the executed profile
   * @param executedAt timestamp of the test execution
   * @param results the individual test case results
   */
  public TlsTestReport {
    if (target == null) {
      throw new IllegalArgumentException("target must not be null");
    }
    if (profile == null) {
      throw new IllegalArgumentException("profile must not be null");
    }
    if (executedAt == null) {
      throw new IllegalArgumentException("executedAt must not be null");
    }
    results = List.copyOf(results == null ? List.of() : results);
  }

  /**
   * Computes the overall verdict of the test run.
   *
   * @return {@link TlsTestVerdict#PASSED} if all contained checks passed, otherwise {@link
   *     TlsTestVerdict#FAILED}
   */
  public TlsTestVerdict overallVerdict() {
    return results.stream().allMatch(result -> result.verdict() == TlsTestVerdict.PASSED)
        ? TlsTestVerdict.PASSED
        : TlsTestVerdict.FAILED;
  }

  /**
   * Searches a contained test result.
   *
   * @param testCase the test case to look up
   * @return the matching result if present
   */
  public Optional<TlsTestResult> findResult(TlsTestCase testCase) {
    return results.stream().filter(result -> result.testCase() == testCase).findFirst();
  }
}
