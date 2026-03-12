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

/**
 * Describes one TLS test execution request.
 *
 * @param target the target endpoint
 * @param profile the profile to execute
 * @param connectionConfiguration TLS client configuration used by the runner
 */
public record TlsTestRequest(
    TlsTestTarget target,
    TlsTestProfile profile,
    TlsConnectionConfiguration connectionConfiguration) {

  /**
   * Creates a validated test request.
   *
   * @param target the target endpoint
   * @param profile the profile to execute
   * @param connectionConfiguration TLS client configuration used by the runner
   */
  public TlsTestRequest {
    if (target == null) {
      throw new IllegalArgumentException("target must not be null");
    }
    if (profile == null) {
      throw new IllegalArgumentException("profile must not be null");
    }
    if (connectionConfiguration == null) {
      connectionConfiguration = TlsConnectionConfiguration.defaults();
    }
  }

  /**
   * Creates a request using the default connection configuration.
   *
   * @param target the target endpoint
   * @param profile the profile to execute
   * @return a request with default connection settings
   */
  public static TlsTestRequest of(TlsTestTarget target, TlsTestProfile profile) {
    return new TlsTestRequest(target, profile, TlsConnectionConfiguration.defaults());
  }
}
