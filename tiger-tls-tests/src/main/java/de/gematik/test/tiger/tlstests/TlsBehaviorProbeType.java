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
 * Identifies one active TLS behavior probe performed by the compliance runner.
 */
public enum TlsBehaviorProbeType {
  /** Probes whether a target accepts a client-initiated TLS 1.2 renegotiation request. */
  TLS_1_2_RENEGOTIATION,
  /** Probes whether a target resumes a second TLS 1.2 session when the same client context is reused. */
  TLS_1_2_SESSION_RESUMPTION,
  /** Probes whether a target advertises secure renegotiation support during a TLS 1.2 handshake. */
  TLS_1_2_SECURE_RENEGOTIATION,
  /** Probes whether a target negotiates the extended-master-secret extension during TLS 1.2. */
  TLS_1_2_EXTENDED_MASTER_SECRET,
  /** Probes whether a target negotiates the encrypt-then-mac extension during a TLS 1.2 CBC handshake. */
  TLS_1_2_ENCRYPT_THEN_MAC,
  /** Probes whether a target rejects a TLS 1.2 fallback handshake via TLS_FALLBACK_SCSV. */
  TLS_1_2_FALLBACK_SCSV_REJECTION,
  /** Probes whether a target provides an OCSP staple during the TLS handshake. */
  OCSP_STAPLING,
  /** Probes whether a target tolerates an unknown ClientHello extension. */
  UNKNOWN_EXTENSION_TOLERANCE,
  /** Probes whether a target rejects a malformed TLS record instead of accepting it silently. */
  MALFORMED_TLS_RECORD_REJECTION
}
