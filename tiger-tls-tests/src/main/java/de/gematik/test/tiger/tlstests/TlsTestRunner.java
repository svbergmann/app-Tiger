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

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/** Executes a small set of active TLS checks against a configured target endpoint. */
public class TlsTestRunner {

  private final TlsClientProbeSupport tlsClientProbeSupport;
  private final TlsOpenSslEvidenceFactory tlsOpenSslEvidenceFactory;

  /**
   * Creates a TLS test runner backed by the default TLS client probe helper.
   */
  public TlsTestRunner() {
    this(new TlsClientProbeSupport(), new TlsOpenSslEvidenceFactory());
  }

  /**
   * Creates a TLS test runner with an injectable probe helper.
   *
   * @param tlsClientProbeSupport low-level TLS client probe helper
   * @param tlsOpenSslEvidenceFactory factory for OpenSSL reproduction evidence
   */
  TlsTestRunner(
      TlsClientProbeSupport tlsClientProbeSupport,
      TlsOpenSslEvidenceFactory tlsOpenSslEvidenceFactory) {
    this.tlsClientProbeSupport = tlsClientProbeSupport;
    this.tlsOpenSslEvidenceFactory = tlsOpenSslEvidenceFactory;
  }

  /**
   * Executes all checks in the requested profile and returns the aggregated report.
   *
   * @param request request describing target, profile, and client settings
   * @return the aggregated test report
   */
  public TlsTestReport run(TlsTestRequest request) {
    final Map<HandshakeKey, ProbeResult> probeCache = new LinkedHashMap<>();
    final List<TlsTestResult> results = new ArrayList<>();

    for (TlsTestCase testCase : request.profile().testCases()) {
      results.add(execute(testCase, request, probeCache));
    }

    return new TlsTestReport(request.target(), request.profile(), Instant.now(), results);
  }

  /**
   * Executes one concrete TLS test case while reusing cached handshake probes where possible.
   *
   * @param testCase test case to execute
   * @param request TLS test request
   * @param probeCache cache of previously executed handshake probes
   * @return one test result
   */
  private TlsTestResult execute(
      TlsTestCase testCase, TlsTestRequest request, Map<HandshakeKey, ProbeResult> probeCache) {
    final TlsProbeEvidenceBuilder evidence =
        tlsOpenSslEvidenceFactory.forProfileTestCase(
            request.target(), request.connectionConfiguration(), testCase);
    return switch (testCase) {
      case HANDSHAKE ->
          buildHandshakeResult(getProbeResult(request, probeCache, null), testCase, evidence);
      case SUPPORTS_TLS_1_2 ->
          buildHandshakeResult(
              getProbeResult(request, probeCache, new String[] {"TLSv1.2"}), testCase, evidence);
      case SUPPORTS_TLS_1_3 ->
          buildHandshakeResult(
              getProbeResult(request, probeCache, new String[] {"TLSv1.3"}), testCase, evidence);
      case PRESENTS_CERTIFICATE ->
          buildCertificatePresenceResult(getProbeResult(request, probeCache, null), evidence);
      case CERTIFICATE_CURRENTLY_VALID ->
          buildCertificateValidityResult(getProbeResult(request, probeCache, null), evidence);
    };
  }

  /**
   * Returns one cached or newly executed handshake probe result.
   *
   * @param request TLS test request
   * @param probeCache cache of previously executed handshake probes
   * @param enabledProtocols protocol override for this probe, or {@code null}
   * @return handshake probe result
   */
  private ProbeResult getProbeResult(
      TlsTestRequest request, Map<HandshakeKey, ProbeResult> probeCache, String[] enabledProtocols) {
    final HandshakeKey key = new HandshakeKey(request, enabledProtocols);
    return probeCache.computeIfAbsent(key, ignored -> probe(request, enabledProtocols));
  }

  /**
   * Executes one concrete TLS handshake probe.
   *
   * @param request TLS test request
   * @param enabledProtocols protocol override for this probe, or {@code null}
   * @return handshake probe result
   */
  private ProbeResult probe(TlsTestRequest request, String[] enabledProtocols) {
    try {
      final SSLContext sslContext =
          tlsClientProbeSupport.buildSslContext(request.connectionConfiguration());
      try (SSLSocket socket =
          tlsClientProbeSupport.openSocket(
              sslContext,
              request.target(),
              request.connectionConfiguration(),
              enabledProtocols,
              null)) {
        socket.startHandshake();

        final SSLSession session = socket.getSession();
        final List<X509Certificate> peerCertificates =
            tlsClientProbeSupport.extractPeerCertificates(session);
        return ProbeResult.success(
            tlsClientProbeSupport.buildSessionSummary(session),
            peerCertificates);
      }
    } catch (Exception e) {
      return ProbeResult.failure(tlsClientProbeSupport.extractRootCauseMessage(e));
    }
  }

  /**
   * Translates one handshake probe into the generic handshake-style TLS test result.
   *
   * @param probeResult handshake probe result
   * @param testCase executed test case
   * @return translated test result
   */
  private TlsTestResult buildHandshakeResult(
      ProbeResult probeResult, TlsTestCase testCase, TlsProbeEvidenceBuilder evidence) {
    if (!probeResult.successful()) {
      evidence.addLogEntry(
          "Handshake failed for " + testCase + ": " + probeResult.failureMessage());
      return new TlsTestResult(
          testCase,
          TlsTestVerdict.FAILED,
          "Handshake failed: " + probeResult.failureMessage(),
          null,
          evidence.build());
    }

    final TlsSessionSummary summary = probeResult.sessionSummary();
    evidence.addLogEntry(
        "Handshake succeeded for "
            + testCase
            + " with "
            + summary.negotiatedProtocol()
            + " / "
            + summary.negotiatedCipherSuite());
    return new TlsTestResult(
        testCase,
        TlsTestVerdict.PASSED,
        "Handshake succeeded with %s and %s"
            .formatted(summary.negotiatedProtocol(), summary.negotiatedCipherSuite()),
        summary,
        evidence.build());
  }

  /**
   * Builds the certificate-presence result from a previously executed handshake probe.
   *
   * @param probeResult handshake probe result
   * @return certificate-presence test result
   */
  private TlsTestResult buildCertificatePresenceResult(
      ProbeResult probeResult, TlsProbeEvidenceBuilder evidence) {
    if (!probeResult.successful()) {
      evidence.addLogEntry(
          "Certificate-presence check skipped because the handshake failed: "
              + probeResult.failureMessage());
      return new TlsTestResult(
          TlsTestCase.PRESENTS_CERTIFICATE,
          TlsTestVerdict.FAILED,
          "Could not inspect certificates because the handshake failed: "
              + probeResult.failureMessage(),
          null,
          evidence.build());
    }

    if (probeResult.peerCertificates().isEmpty()) {
      evidence.addLogEntry("Handshake completed without any peer certificates");
      return new TlsTestResult(
          TlsTestCase.PRESENTS_CERTIFICATE,
          TlsTestVerdict.FAILED,
          "Handshake succeeded but the peer did not present any certificate",
          probeResult.sessionSummary(),
          evidence.build());
    }

    evidence.addLogEntry(
        "Peer presented " + probeResult.peerCertificates().size() + " certificate(s)");
    return new TlsTestResult(
        TlsTestCase.PRESENTS_CERTIFICATE,
        TlsTestVerdict.PASSED,
        "Peer presented %d certificate(s)".formatted(probeResult.peerCertificates().size()),
        probeResult.sessionSummary(),
        evidence.build());
  }

  /**
   * Builds the certificate-validity result from a previously executed handshake probe.
   *
   * @param probeResult handshake probe result
   * @return certificate-validity test result
   */
  private TlsTestResult buildCertificateValidityResult(
      ProbeResult probeResult, TlsProbeEvidenceBuilder evidence) {
    if (!probeResult.successful()) {
      evidence.addLogEntry(
          "Certificate-validity check skipped because the handshake failed: "
              + probeResult.failureMessage());
      return new TlsTestResult(
          TlsTestCase.CERTIFICATE_CURRENTLY_VALID,
          TlsTestVerdict.FAILED,
          "Could not validate certificate dates because the handshake failed: "
              + probeResult.failureMessage(),
          null,
          evidence.build());
    }

    if (probeResult.peerCertificates().isEmpty()) {
      evidence.addLogEntry("No peer certificate was available for date validation");
      return new TlsTestResult(
          TlsTestCase.CERTIFICATE_CURRENTLY_VALID,
          TlsTestVerdict.FAILED,
          "Handshake succeeded but no peer certificate was available for validity checks",
          probeResult.sessionSummary(),
          evidence.build());
    }

    try {
      final Date now = new Date();
      for (X509Certificate certificate : probeResult.peerCertificates()) {
        certificate.checkValidity(now);
      }
      evidence.addLogEntry("All peer certificates were valid at " + now.toInstant());
      return new TlsTestResult(
          TlsTestCase.CERTIFICATE_CURRENTLY_VALID,
          TlsTestVerdict.PASSED,
          "All presented certificates are currently valid",
          probeResult.sessionSummary(),
          evidence.build());
    } catch (Exception e) {
      evidence.addLogEntry(
          "Certificate-validity check failed with " + extractRootCauseMessage(e));
      return new TlsTestResult(
          TlsTestCase.CERTIFICATE_CURRENTLY_VALID,
          TlsTestVerdict.FAILED,
          "Certificate validity check failed: " + extractRootCauseMessage(e),
          probeResult.sessionSummary(),
          evidence.build());
    }
  }

  /**
   * Extracts the root-cause message from an exception hierarchy.
   *
   * @param throwable original exception
   * @return root-cause message or class name
   */
  private String extractRootCauseMessage(Throwable throwable) {
    return tlsClientProbeSupport.extractRootCauseMessage(throwable);
  }

  /**
   * Cache key for handshake probe reuse across test cases within one report execution.
   *
   * @param request original TLS test request
   * @param enabledProtocols effective protocol override applied to the probe
   */
  private record HandshakeKey(TlsTestRequest request, List<String> enabledProtocols) {

    /**
     * Creates a cache key from an optional protocol override array.
     *
     * @param request original TLS test request
     * @param enabledProtocols protocol override array, or {@code null}
     */
    private HandshakeKey(TlsTestRequest request, String[] enabledProtocols) {
      this(request, enabledProtocols == null ? List.of() : List.of(enabledProtocols));
    }
  }

  /**
   * Internal raw handshake probe result reused by multiple higher-level test cases.
   *
   * @param successful whether the handshake succeeded
   * @param failureMessage root-cause failure message for failed probes
   * @param sessionSummary negotiated session summary for successful probes
   * @param peerCertificates extracted peer certificate chain for successful probes
   */
  private record ProbeResult(
      boolean successful,
      String failureMessage,
      TlsSessionSummary sessionSummary,
      List<X509Certificate> peerCertificates) {

    /**
     * Creates a successful raw probe result.
     *
     * @param sessionSummary negotiated session summary
     * @param peerCertificates extracted peer certificate chain
     * @return successful raw probe result
     */
    private static ProbeResult success(
        TlsSessionSummary sessionSummary, List<X509Certificate> peerCertificates) {
      return new ProbeResult(true, null, sessionSummary, List.copyOf(peerCertificates));
    }

    /**
     * Creates a failed raw probe result.
     *
     * @param failureMessage root-cause failure message
     * @return failed raw probe result
     */
    private static ProbeResult failure(String failureMessage) {
      return new ProbeResult(false, failureMessage, null, List.of());
    }
  }
}
