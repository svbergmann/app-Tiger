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
 * Summarizes the relevant outcome of a successful TLS handshake.
 *
 * @param negotiatedProtocol the negotiated TLS protocol version
 * @param negotiatedCipherSuite the negotiated cipher suite
 * @param certificateSubjects the subject distinguished names presented by the peer
 */
public record TlsSessionSummary(
    String negotiatedProtocol, String negotiatedCipherSuite, List<String> certificateSubjects) {

  /**
   * Creates an immutable session summary.
   *
   * @param negotiatedProtocol the negotiated TLS protocol version
   * @param negotiatedCipherSuite the negotiated cipher suite
   * @param certificateSubjects the subject distinguished names presented by the peer
   */
  public TlsSessionSummary {
    if (negotiatedProtocol == null || negotiatedProtocol.isBlank()) {
      throw new IllegalArgumentException("negotiatedProtocol must not be blank");
    }
    if (negotiatedCipherSuite == null || negotiatedCipherSuite.isBlank()) {
      throw new IllegalArgumentException("negotiatedCipherSuite must not be blank");
    }
    certificateSubjects = List.copyOf(certificateSubjects == null ? List.of() : certificateSubjects);
  }
}
