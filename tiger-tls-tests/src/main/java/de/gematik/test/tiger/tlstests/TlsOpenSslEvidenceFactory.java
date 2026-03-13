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
 * Creates best-effort OpenSSL reproduction commands for TLS probes.
 */
final class TlsOpenSslEvidenceFactory {

  /**
   * Creates the helper.
   */
  TlsOpenSslEvidenceFactory() {}

  /**
   * Builds evidence for probing one protocol token.
   *
   * @param target probed target endpoint
   * @param configuration probe configuration
   * @param protocol protocol token under test
   * @return evidence builder populated with reproduction data
   */
  TlsProbeEvidenceBuilder forProtocolProbe(
      TlsTestTarget target, TlsConnectionConfiguration configuration, String protocol) {
    final TlsProbeEvidenceBuilder builder = baseEvidence(target, configuration);
    builder.addReproductionCommand(
        baseCommand(target, configuration)
            + " "
            + protocolCommandOption(protocol)
            + " </dev/null");
    builder.addLogEntry("OpenSSL reproduction prepared for protocol " + protocol);
    return builder;
  }

  /**
   * Builds evidence for probing one cipher suite token.
   *
   * @param target probed target endpoint
   * @param configuration probe configuration
   * @param cipherSuite cipher suite token under test
   * @return evidence builder populated with reproduction data
   */
  TlsProbeEvidenceBuilder forCipherSuiteProbe(
      TlsTestTarget target, TlsConnectionConfiguration configuration, String cipherSuite) {
    final TlsProbeEvidenceBuilder builder = baseEvidence(target, configuration);
    if (isTls13CipherSuite(cipherSuite)) {
      builder.addReproductionCommand(
          baseCommand(target, configuration)
              + " -ciphersuites '"
              + cipherSuite
              + "' </dev/null");
    } else {
      builder.addReproductionCommand(
          "openssl ciphers -stdname | grep -F '"
              + cipherSuite
              + "'");
      builder.addReproductionCommand(
          baseCommand(target, configuration)
              + " -cipher '<OPENSSL_TLS12_CIPHER_NAME>' </dev/null");
      builder.addNote(
          "TLS 1.2 and earlier cipher suites use OpenSSL-specific names. Resolve the OpenSSL name with the first command before running the second command.");
    }
    builder.addLogEntry("OpenSSL reproduction prepared for cipher suite " + cipherSuite);
    return builder;
  }

  /**
   * Builds evidence for probing one ALPN application protocol token.
   *
   * @param target probed target endpoint
   * @param configuration probe configuration
   * @param applicationProtocol application protocol token under test
   * @return evidence builder populated with reproduction data
   */
  TlsProbeEvidenceBuilder forApplicationProtocolProbe(
      TlsTestTarget target,
      TlsConnectionConfiguration configuration,
      String applicationProtocol) {
    final TlsProbeEvidenceBuilder builder = baseEvidence(target, configuration);
    builder.addReproductionCommand(
        baseCommand(target, configuration)
            + " -alpn '"
            + applicationProtocol
            + "' </dev/null");
    builder.addLogEntry(
        "OpenSSL reproduction prepared for ALPN application protocol " + applicationProtocol);
    return builder;
  }

  /**
   * Builds evidence for probing one named group token.
   *
   * @param target probed target endpoint
   * @param configuration probe configuration
   * @param namedGroup named-group token under test
   * @return evidence builder populated with reproduction data
   */
  TlsProbeEvidenceBuilder forNamedGroupProbe(
      TlsTestTarget target, TlsConnectionConfiguration configuration, String namedGroup) {
    final TlsProbeEvidenceBuilder builder = baseEvidence(target, configuration);
    builder.addReproductionCommand(
        baseCommand(target, configuration) + " -groups '" + namedGroup + "' </dev/null");
    builder.addLogEntry("OpenSSL reproduction prepared for named group " + namedGroup);
    return builder;
  }

  /**
   * Builds evidence for probing one signature-scheme token.
   *
   * @param target probed target endpoint
   * @param configuration probe configuration
   * @param signatureScheme signature-scheme token under test
   * @return evidence builder populated with reproduction data
   */
  TlsProbeEvidenceBuilder forSignatureSchemeProbe(
      TlsTestTarget target, TlsConnectionConfiguration configuration, String signatureScheme) {
    final TlsProbeEvidenceBuilder builder = baseEvidence(target, configuration);
    builder.addReproductionCommand(
        baseCommand(target, configuration) + " -sigalgs '" + signatureScheme + "' </dev/null");
    builder.addLogEntry(
        "OpenSSL reproduction prepared for signature scheme " + signatureScheme);
    return builder;
  }

  /**
   * Builds evidence for one built-in profile test case.
   *
   * @param target probed target endpoint
   * @param configuration probe configuration
   * @param testCase built-in TLS test case
   * @return evidence builder populated with reproduction data
   */
  TlsProbeEvidenceBuilder forProfileTestCase(
      TlsTestTarget target, TlsConnectionConfiguration configuration, TlsTestCase testCase) {
    final TlsProbeEvidenceBuilder builder = baseEvidence(target, configuration);
    switch (testCase) {
      case HANDSHAKE, PRESENTS_CERTIFICATE ->
          builder.addReproductionCommand(
              baseCommand(target, configuration) + " -showcerts </dev/null");
      case SUPPORTS_TLS_1_2 ->
          builder.addReproductionCommand(
              baseCommand(target, configuration) + " -tls1_2 </dev/null");
      case SUPPORTS_TLS_1_3 ->
          builder.addReproductionCommand(
              baseCommand(target, configuration) + " -tls1_3 </dev/null");
      case CERTIFICATE_CURRENTLY_VALID -> {
        builder.addReproductionCommand(
            baseCommand(target, configuration) + " -showcerts </dev/null");
        builder.addNote(
            "Certificate validity checks require extracting the peer certificate chain from the OpenSSL output before running additional x509 date checks.");
      }
    }
    builder.addLogEntry("OpenSSL reproduction prepared for profile test case " + testCase);
    return builder;
  }

  /**
   * Builds evidence for one TLS behavior probe.
   *
   * @param target probed target endpoint
   * @param configuration probe configuration
   * @param probeType behavior probe type
   * @return evidence builder populated with reproduction data
   */
  TlsProbeEvidenceBuilder forBehaviorProbe(
      TlsTestTarget target,
      TlsConnectionConfiguration configuration,
      TlsBehaviorProbeType probeType) {
    final TlsProbeEvidenceBuilder builder = baseEvidence(target, configuration);
    switch (probeType) {
      case TLS_1_2_RENEGOTIATION ->
          builder.addReproductionCommand(
              "printf 'R\\nQ\\n' | " + baseCommand(target, configuration) + " -tls1_2");
      case TLS_1_2_SESSION_RESUMPTION -> {
        builder.addReproductionCommand(
            baseCommand(target, configuration)
                + " -tls1_2 -sess_out /tmp/tiger_tls_session.pem </dev/null");
        builder.addReproductionCommand(
            baseCommand(target, configuration)
                + " -tls1_2 -sess_in /tmp/tiger_tls_session.pem </dev/null");
      }
      case OCSP_STAPLING ->
          builder.addReproductionCommand(
              baseCommand(target, configuration) + " -status </dev/null");
      case MALFORMED_TLS_RECORD_REJECTION ->
          builder.addNote(
              "OpenSSL s_client does not expose a direct malformed-record mode for this probe.");
      case TLS_1_2_SECURE_RENEGOTIATION ->
          builder.addReproductionCommand(
              baseCommand(target, configuration) + " -tls1_2 -tlsextdebug </dev/null");
      case TLS_1_2_EXTENDED_MASTER_SECRET ->
          builder.addReproductionCommand(
              baseCommand(target, configuration) + " -tls1_2 -tlsextdebug </dev/null");
      case TLS_1_2_ENCRYPT_THEN_MAC -> {
        builder.addReproductionCommand(
            "openssl ciphers -stdname | grep -E 'TLS_(ECDHE|DHE|RSA)_(RSA|ECDSA)?_?WITH_AES_(128|256)_CBC_SHA(256)?'");
        builder.addReproductionCommand(
            baseCommand(target, configuration)
                + " -tls1_2 -cipher '<OPENSSL_TLS12_CBC_CIPHER_NAME>' -tlsextdebug </dev/null");
        builder.addNote(
            "The encrypt-then-mac probe requires a TLS 1.2 CBC cipher suite. Resolve one OpenSSL CBC cipher name with the first command before running the second command.");
      }
      case TLS_1_2_FALLBACK_SCSV_REJECTION ->
          builder.addReproductionCommand(
              baseCommand(target, configuration) + " -tls1_2 -fallback_scsv </dev/null");
      case UNKNOWN_EXTENSION_TOLERANCE ->
          builder.addNote(
              "OpenSSL s_client does not expose a generic unknown-extension injection mode for this probe.");
    }
    builder.addLogEntry("OpenSSL reproduction prepared for behavior probe " + probeType);
    return builder;
  }

  /**
   * Creates a builder with configuration translation notes.
   *
   * @param target probed target endpoint
   * @param configuration probe configuration
   * @return evidence builder seeded with generic notes
   */
  private TlsProbeEvidenceBuilder baseEvidence(
      TlsTestTarget target, TlsConnectionConfiguration configuration) {
    final TlsProbeEvidenceBuilder builder = new TlsProbeEvidenceBuilder();
    builder.addLogEntry(
        "Prepared evidence for target "
            + target.host()
            + ":"
            + target.port()
            + " with SNI "
            + target.effectiveSniHostName());
    if (!configuration.trustAllCertificates()) {
      builder.addNote(
          "This probe uses custom trust material or hostname validation. OpenSSL reproduction may require additional PEM conversion for Tiger identities.");
    }
    if (configuration.clientIdentity() != null) {
      builder.addNote(
          "Configured Tiger client identities use PKCS#12 compact tokens. OpenSSL reproduction requires separate PEM certificate and key files.");
    }
    if (!configuration.enabledProtocols().isEmpty()) {
      builder.addNote("The Tiger probe configuration already restricts protocols to " + configuration.enabledProtocols() + ".");
    }
    if (!configuration.enabledCipherSuites().isEmpty()) {
      builder.addNote("The Tiger probe configuration already restricts cipher suites to " + configuration.enabledCipherSuites() + ".");
    }
    return builder;
  }

  /**
   * Builds the common OpenSSL command prefix for one target and configuration.
   *
   * @param target probed target endpoint
   * @param configuration probe configuration
   * @return common OpenSSL command prefix
   */
  private String baseCommand(TlsTestTarget target, TlsConnectionConfiguration configuration) {
    final StringBuilder command =
        new StringBuilder("openssl s_client -connect ")
            .append(shellQuote(target.host()))
            .append(":")
            .append(target.port());
    if (!target.effectiveSniHostName().isBlank()) {
      command.append(" -servername ").append(shellQuote(target.effectiveSniHostName()));
    }
    if (configuration.hostnameVerification()) {
      command.append(" -verify_hostname ").append(shellQuote(target.host()));
    }
    return command.toString();
  }

  /**
   * Maps a Java-style protocol token to the matching OpenSSL option.
   *
   * @param protocol Java-style protocol token
   * @return OpenSSL protocol option
   */
  private String protocolCommandOption(String protocol) {
    return switch (protocol) {
      case "TLSv1", "TLSv1.0" -> "-tls1";
      case "TLSv1.1" -> "-tls1_1";
      case "TLSv1.2" -> "-tls1_2";
      case "TLSv1.3" -> "-tls1_3";
      default -> throw new IllegalArgumentException("Unsupported TLS protocol token: " + protocol);
    };
  }

  /**
   * Determines whether the cipher suite belongs to TLS 1.3, where OpenSSL uses IANA names
   * directly.
   *
   * @param cipherSuite cipher suite token
   * @return {@code true} if the cipher suite is a TLS 1.3 cipher suite
   */
  private boolean isTls13CipherSuite(String cipherSuite) {
    return List.of(
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_CCM_SHA256",
            "TLS_AES_128_CCM_8_SHA256")
        .contains(cipherSuite);
  }

  /**
   * Escapes one shell token conservatively for the generated commands.
   *
   * @param value shell token value
   * @return single-quoted shell token
   */
  private String shellQuote(String value) {
    return "'" + value.replace("'", "'\"'\"'") + "'";
  }
}
