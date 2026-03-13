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

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatusRequest;
import org.bouncycastle.tls.CertificateStatusType;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.ECPointFormat;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.NameType;
import org.bouncycastle.tls.OCSPStatusRequest;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Executes deeper active TLS compliance probes such as protocol scans, cipher-suite scans,
 * renegotiation attempts, low-level extension probes, and session-resumption attempts.
 */
public class TlsComplianceRunner {

  private static final Logger LOG = LoggerFactory.getLogger(TlsComplianceRunner.class);
  private static final int UNKNOWN_EXTENSION_TYPE = 65486;
  private static final String LOW_LEVEL_VALIDATION_NOTE =
      "This low-level probe inspects server capabilities and does not apply JSSE PKIX validation.";

  private final TlsTestRunner tlsTestRunner;
  private final TlsClientProbeSupport tlsClientProbeSupport;
  private final TlsOpenSslEvidenceFactory tlsOpenSslEvidenceFactory;

  /**
   * Creates a compliance runner backed by the default TLS test runner and probe helpers.
   */
  public TlsComplianceRunner() {
    this(new TlsTestRunner(), new TlsClientProbeSupport(), new TlsOpenSslEvidenceFactory());
  }

  /**
   * Creates a compliance runner with injectable collaborators for testing.
   *
   * @param tlsTestRunner profile runner reused for handshake-based scans
   * @param tlsClientProbeSupport low-level TLS client probe helper
   * @param tlsOpenSslEvidenceFactory factory for OpenSSL reproduction evidence
   */
  TlsComplianceRunner(
      TlsTestRunner tlsTestRunner,
      TlsClientProbeSupport tlsClientProbeSupport,
      TlsOpenSslEvidenceFactory tlsOpenSslEvidenceFactory) {
    this.tlsTestRunner = tlsTestRunner;
    this.tlsClientProbeSupport = tlsClientProbeSupport;
    this.tlsOpenSslEvidenceFactory = tlsOpenSslEvidenceFactory;
  }

  /**
   * Scans a list of protocol versions against a target endpoint.
   *
   * @param target target endpoint to probe
   * @param protocols protocol versions to test
   * @param configuration base TLS client configuration
   * @return structured protocol support report
   */
  public TlsFeatureSupportReport scanProtocols(
      TlsTestTarget target, List<String> protocols, TlsConnectionConfiguration configuration) {
    LOG.info("Running TLS protocol scan against {}:{} for {}", target.host(), target.port(), protocols);
    return scanFeatures(target, protocols, configuration, TlsScannedFeatureType.PROTOCOL);
  }

  /**
   * Scans a list of cipher suites against a target endpoint.
   *
   * @param target target endpoint to probe
   * @param cipherSuites cipher suites to test
   * @param configuration base TLS client configuration
   * @return structured cipher-suite support report
   */
  public TlsFeatureSupportReport scanCipherSuites(
      TlsTestTarget target,
      List<String> cipherSuites,
      TlsConnectionConfiguration configuration) {
    LOG.info(
        "Running TLS cipher-suite scan against {}:{} for {}",
        target.host(),
        target.port(),
        cipherSuites);
    return scanFeatures(target, cipherSuites, configuration, TlsScannedFeatureType.CIPHER_SUITE);
  }

  /**
   * Scans a list of TLS named groups against a target endpoint.
   *
   * @param target target endpoint to probe
   * @param namedGroups named groups to test
   * @param configuration base TLS client configuration
   * @return structured named-group support report
   */
  public TlsFeatureSupportReport scanNamedGroups(
      TlsTestTarget target,
      List<String> namedGroups,
      TlsConnectionConfiguration configuration) {
    LOG.info(
        "Running TLS named-group scan against {}:{} for {}",
        target.host(),
        target.port(),
        namedGroups);
    return scanFeatures(target, namedGroups, configuration, TlsScannedFeatureType.NAMED_GROUP);
  }

  /**
   * Scans a list of TLS signature schemes against a target endpoint.
   *
   * @param target target endpoint to probe
   * @param signatureSchemes signature schemes to test
   * @param configuration base TLS client configuration
   * @return structured signature-scheme support report
   */
  public TlsFeatureSupportReport scanSignatureSchemes(
      TlsTestTarget target,
      List<String> signatureSchemes,
      TlsConnectionConfiguration configuration) {
    LOG.info(
        "Running TLS signature-scheme scan against {}:{} for {}",
        target.host(),
        target.port(),
        signatureSchemes);
    return scanFeatures(
        target, signatureSchemes, configuration, TlsScannedFeatureType.SIGNATURE_SCHEME);
  }

  /**
   * Attempts a client-initiated TLS 1.2 renegotiation against a target endpoint.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @return behavior probe report for TLS 1.2 renegotiation
   */
  public TlsBehaviorProbeReport probeTls12Renegotiation(
      TlsTestTarget target, TlsConnectionConfiguration configuration) {
    final TlsConnectionConfiguration tls12Configuration = withTls12Only(configuration);
    final TlsProbeEvidenceBuilder evidence =
        tlsOpenSslEvidenceFactory.forBehaviorProbe(
            target, tls12Configuration, TlsBehaviorProbeType.TLS_1_2_RENEGOTIATION);
    evidence.addLogEntry("Starting TLS 1.2 renegotiation probe");
    try {
      final SSLContext sslContext = tlsClientProbeSupport.buildSslContext(tls12Configuration);
      try (SSLSocket socket =
          tlsClientProbeSupport.openSocket(
              sslContext, target, tls12Configuration, new String[] {"TLSv1.2"}, null)) {
        socket.startHandshake();
        final TlsSessionSummary initialSessionSummary =
            tlsClientProbeSupport.buildSessionSummary(socket.getSession());
        evidence.addLogEntry(
            "Initial TLS 1.2 handshake succeeded with "
                + initialSessionSummary.negotiatedProtocol()
                + " / "
                + initialSessionSummary.negotiatedCipherSuite());

        // A second handshake request on the same TLS 1.2 socket triggers renegotiation on stacks
        // that still support it.
        socket.startHandshake();
        final TlsSessionSummary followUpSessionSummary =
            tlsClientProbeSupport.buildSessionSummary(socket.getSession());
        evidence.addLogEntry(
            "Follow-up TLS 1.2 handshake succeeded with "
                + followUpSessionSummary.negotiatedProtocol()
                + " / "
                + followUpSessionSummary.negotiatedCipherSuite());
        return buildBehaviorReport(
            target,
            TlsBehaviorProbeType.TLS_1_2_RENEGOTIATION,
            TlsTestVerdict.PASSED,
            "TLS 1.2 renegotiation succeeded",
            initialSessionSummary,
            followUpSessionSummary,
            evidence);
      }
    } catch (Exception e) {
      evidence.addLogEntry(
          "Renegotiation probe failed with "
              + tlsClientProbeSupport.extractRootCauseMessage(e));
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.TLS_1_2_RENEGOTIATION,
          TlsTestVerdict.FAILED,
          "TLS 1.2 renegotiation failed: " + tlsClientProbeSupport.extractRootCauseMessage(e),
          null,
          null,
          evidence);
    }
  }

  /**
   * Attempts TLS 1.2 session resumption by reconnecting with the same client-side SSL context.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @return behavior probe report for TLS 1.2 session resumption
   */
  public TlsBehaviorProbeReport probeTls12SessionResumption(
      TlsTestTarget target, TlsConnectionConfiguration configuration) {
    final TlsConnectionConfiguration tls12Configuration = withTls12Only(configuration);
    final TlsProbeEvidenceBuilder evidence =
        tlsOpenSslEvidenceFactory.forBehaviorProbe(
            target, tls12Configuration, TlsBehaviorProbeType.TLS_1_2_SESSION_RESUMPTION);
    evidence.addLogEntry("Starting TLS 1.2 session-resumption probe");
    try {
      final SSLContext sslContext = tlsClientProbeSupport.buildSslContext(tls12Configuration);
      final HandshakeAttempt firstAttempt =
          performHandshake(target, tls12Configuration, sslContext, "TLSv1.2");
      final HandshakeAttempt secondAttempt =
          performHandshake(target, tls12Configuration, sslContext, "TLSv1.2");
      evidence.addLogEntry("First session identifier length: " + firstAttempt.sessionId().length);
      evidence.addLogEntry("Second session identifier length: " + secondAttempt.sessionId().length);

      if (firstAttempt.sessionId().length == 0 || secondAttempt.sessionId().length == 0) {
        return buildBehaviorReport(
            target,
            TlsBehaviorProbeType.TLS_1_2_SESSION_RESUMPTION,
            TlsTestVerdict.FAILED,
            "TLS 1.2 session resumption could not be verified because the server did not expose reusable session identifiers",
            firstAttempt.sessionSummary(),
            secondAttempt.sessionSummary(),
            evidence);
      }

      final boolean resumed = Arrays.equals(firstAttempt.sessionId(), secondAttempt.sessionId());
      evidence.addLogEntry("Session identifier reuse observed: " + resumed);
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.TLS_1_2_SESSION_RESUMPTION,
          resumed ? TlsTestVerdict.PASSED : TlsTestVerdict.FAILED,
          resumed
              ? "TLS 1.2 session resumption succeeded"
              : "TLS 1.2 session resumption was not observed on the second connection",
          firstAttempt.sessionSummary(),
          secondAttempt.sessionSummary(),
          evidence);
    } catch (Exception e) {
      evidence.addLogEntry(
          "Session-resumption probe failed with "
              + tlsClientProbeSupport.extractRootCauseMessage(e));
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.TLS_1_2_SESSION_RESUMPTION,
          TlsTestVerdict.FAILED,
          "TLS 1.2 session resumption failed: " + tlsClientProbeSupport.extractRootCauseMessage(e),
          null,
          null,
          evidence);
    }
  }

  /**
   * Attempts a TLS handshake with an OCSP status request and checks whether the peer stapled a
   * response.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @return behavior probe report for OCSP stapling support
   */
  public TlsBehaviorProbeReport probeOcspStapling(
      TlsTestTarget target, TlsConnectionConfiguration configuration) {
    final TlsProbeEvidenceBuilder evidence =
        tlsOpenSslEvidenceFactory.forBehaviorProbe(
            target, configuration, TlsBehaviorProbeType.OCSP_STAPLING);
    evidence.addNote(LOW_LEVEL_VALIDATION_NOTE);
    evidence.addLogEntry("Starting OCSP stapling probe");
    final InspectableTlsClient client =
        new InspectableTlsClient(target, configuration, LowLevelClientOptions.withOcspStapling());
    try {
      final TlsSessionSummary sessionSummary = connectLowLevel(target, configuration, client, evidence);
      final TlsTestVerdict verdict =
          client.ocspStaplingPresent() ? TlsTestVerdict.PASSED : TlsTestVerdict.FAILED;
      final String details =
          client.ocspStaplingPresent()
              ? "Peer returned a stapled OCSP response"
              : "Peer did not return a stapled OCSP response";
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.OCSP_STAPLING,
          verdict,
          details,
          sessionSummary,
          null,
          evidence);
    } catch (Exception e) {
      recordClientAlerts(client, evidence);
      evidence.addLogEntry(
          "OCSP stapling probe failed with "
              + tlsClientProbeSupport.extractRootCauseMessage(e));
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.OCSP_STAPLING,
          TlsTestVerdict.FAILED,
          "OCSP stapling probe failed: " + tlsClientProbeSupport.extractRootCauseMessage(e),
          null,
          null,
          evidence);
    }
  }

  /**
   * Probes whether the server negotiated secure renegotiation information during a TLS 1.2
   * handshake.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @return behavior probe report for secure renegotiation support
   */
  public TlsBehaviorProbeReport probeTls12SecureRenegotiationSupport(
      TlsTestTarget target, TlsConnectionConfiguration configuration) {
    final TlsConnectionConfiguration tls12Configuration = withTls12Only(configuration);
    final TlsProbeEvidenceBuilder evidence =
        tlsOpenSslEvidenceFactory.forBehaviorProbe(
            target, tls12Configuration, TlsBehaviorProbeType.TLS_1_2_SECURE_RENEGOTIATION);
    evidence.addNote(LOW_LEVEL_VALIDATION_NOTE);
    evidence.addLogEntry("Starting TLS 1.2 secure-renegotiation-support probe");
    final InspectableTlsClient client =
        new InspectableTlsClient(target, tls12Configuration, LowLevelClientOptions.defaults());
    try {
      final TlsSessionSummary sessionSummary =
          connectLowLevel(target, tls12Configuration, client, evidence);
      final boolean supported = client.secureRenegotiationSupported();
      evidence.addLogEntry("Secure renegotiation advertised: " + supported);
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.TLS_1_2_SECURE_RENEGOTIATION,
          supported ? TlsTestVerdict.PASSED : TlsTestVerdict.FAILED,
          supported
              ? "Peer advertised secure renegotiation support during a TLS 1.2 handshake"
              : "Peer did not advertise secure renegotiation support during a TLS 1.2 handshake",
          sessionSummary,
          null,
          evidence);
    } catch (Exception e) {
      recordClientAlerts(client, evidence);
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.TLS_1_2_SECURE_RENEGOTIATION,
          TlsTestVerdict.FAILED,
          "TLS 1.2 secure renegotiation probe failed: "
              + tlsClientProbeSupport.extractRootCauseMessage(e),
          null,
          null,
          evidence);
    }
  }

  /**
   * Probes whether the server negotiated the extended-master-secret extension during a TLS 1.2
   * handshake.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @return behavior probe report for extended-master-secret support
   */
  public TlsBehaviorProbeReport probeTls12ExtendedMasterSecretSupport(
      TlsTestTarget target, TlsConnectionConfiguration configuration) {
    final TlsConnectionConfiguration tls12Configuration = withTls12Only(configuration);
    final TlsProbeEvidenceBuilder evidence =
        tlsOpenSslEvidenceFactory.forBehaviorProbe(
            target, tls12Configuration, TlsBehaviorProbeType.TLS_1_2_EXTENDED_MASTER_SECRET);
    evidence.addNote(LOW_LEVEL_VALIDATION_NOTE);
    evidence.addLogEntry("Starting TLS 1.2 extended-master-secret probe");
    final InspectableTlsClient client =
        new InspectableTlsClient(target, tls12Configuration, LowLevelClientOptions.defaults());
    try {
      final TlsSessionSummary sessionSummary =
          connectLowLevel(target, tls12Configuration, client, evidence);
      final boolean supported = client.extendedMasterSecretSupported();
      evidence.addLogEntry("Extended master secret advertised: " + supported);
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.TLS_1_2_EXTENDED_MASTER_SECRET,
          supported ? TlsTestVerdict.PASSED : TlsTestVerdict.FAILED,
          supported
              ? "Peer negotiated the extended-master-secret extension during a TLS 1.2 handshake"
              : "Peer did not negotiate the extended-master-secret extension during a TLS 1.2 handshake",
          sessionSummary,
          null,
          evidence);
    } catch (Exception e) {
      recordClientAlerts(client, evidence);
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.TLS_1_2_EXTENDED_MASTER_SECRET,
          TlsTestVerdict.FAILED,
          "TLS 1.2 extended master secret probe failed: "
              + tlsClientProbeSupport.extractRootCauseMessage(e),
          null,
          null,
          evidence);
    }
  }

  /**
   * Probes whether the server rejects a TLS 1.2 fallback handshake with the fallback-SCSV signal.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @return behavior probe report for fallback-SCSV rejection
   */
  public TlsBehaviorProbeReport probeTls12FallbackScsvRejection(
      TlsTestTarget target, TlsConnectionConfiguration configuration) {
    final TlsConnectionConfiguration tls12Configuration = withTls12Only(configuration);
    final TlsProbeEvidenceBuilder evidence =
        tlsOpenSslEvidenceFactory.forBehaviorProbe(
            target, tls12Configuration, TlsBehaviorProbeType.TLS_1_2_FALLBACK_SCSV_REJECTION);
    evidence.addNote(LOW_LEVEL_VALIDATION_NOTE);
    evidence.addLogEntry("Starting TLS 1.2 fallback-SCSV rejection probe");
    final InspectableTlsClient client =
        new InspectableTlsClient(
            target, tls12Configuration, LowLevelClientOptions.withFallbackScsv());
    try {
      final TlsSessionSummary sessionSummary =
          connectLowLevel(target, tls12Configuration, client, evidence);
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.TLS_1_2_FALLBACK_SCSV_REJECTION,
          TlsTestVerdict.FAILED,
          "Peer accepted a TLS 1.2 fallback handshake instead of rejecting it with inappropriate_fallback",
          sessionSummary,
          null,
          evidence);
    } catch (Exception e) {
      recordClientAlerts(client, evidence);
      final boolean rejectedForFallback =
          client.receivedAlertDescription() != null
              && client.receivedAlertDescription() == AlertDescription.inappropriate_fallback;
      evidence.addLogEntry("Fallback rejection observed: " + rejectedForFallback);
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.TLS_1_2_FALLBACK_SCSV_REJECTION,
          rejectedForFallback ? TlsTestVerdict.PASSED : TlsTestVerdict.FAILED,
          rejectedForFallback
              ? "Peer rejected the fallback handshake with inappropriate_fallback"
              : "TLS 1.2 fallback-SCSV probe failed without observing inappropriate_fallback: "
                  + tlsClientProbeSupport.extractRootCauseMessage(e),
          null,
          null,
          evidence);
    }
  }

  /**
   * Probes whether the server tolerates an unknown ClientHello extension instead of aborting the
   * handshake.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @return behavior probe report for unknown-extension tolerance
   */
  public TlsBehaviorProbeReport probeUnknownExtensionTolerance(
      TlsTestTarget target, TlsConnectionConfiguration configuration) {
    final TlsProbeEvidenceBuilder evidence =
        tlsOpenSslEvidenceFactory.forBehaviorProbe(
            target, configuration, TlsBehaviorProbeType.UNKNOWN_EXTENSION_TOLERANCE);
    evidence.addNote(LOW_LEVEL_VALIDATION_NOTE);
    evidence.addLogEntry("Starting unknown-extension-tolerance probe");
    final InspectableTlsClient client =
        new InspectableTlsClient(
            target, configuration, LowLevelClientOptions.withUnknownExtension());
    try {
      final TlsSessionSummary sessionSummary = connectLowLevel(target, configuration, client, evidence);
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.UNKNOWN_EXTENSION_TOLERANCE,
          TlsTestVerdict.PASSED,
          "Peer tolerated an unknown ClientHello extension and completed the handshake",
          sessionSummary,
          null,
          evidence);
    } catch (Exception e) {
      recordClientAlerts(client, evidence);
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.UNKNOWN_EXTENSION_TOLERANCE,
          TlsTestVerdict.FAILED,
          "Peer did not tolerate an unknown ClientHello extension: "
              + tlsClientProbeSupport.extractRootCauseMessage(e),
          null,
          null,
          evidence);
    }
  }

  /**
   * Sends a malformed TLS record and checks whether the peer rejects it.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @return behavior probe report for malformed-record rejection
   */
  public TlsBehaviorProbeReport probeMalformedTlsRecordRejection(
      TlsTestTarget target, TlsConnectionConfiguration configuration) {
    final TlsProbeEvidenceBuilder evidence =
        tlsOpenSslEvidenceFactory.forBehaviorProbe(
            target, configuration, TlsBehaviorProbeType.MALFORMED_TLS_RECORD_REJECTION);
    evidence.addLogEntry("Starting malformed TLS record rejection probe");
    try (Socket socket = openPlainSocket(target, configuration)) {
      socket.getOutputStream().write(malformedClientHelloRecord());
      socket.getOutputStream().flush();
      socket.shutdownOutput();

      final int response = socket.getInputStream().read();
      evidence.addLogEntry("First byte returned by peer after malformed record: " + response);
      if (response < 0) {
        return buildBehaviorReport(
            target,
            TlsBehaviorProbeType.MALFORMED_TLS_RECORD_REJECTION,
            TlsTestVerdict.PASSED,
            "Peer rejected the malformed TLS record by closing the connection",
            null,
            null,
            evidence);
      }
      if (response == 0x15) {
        return buildBehaviorReport(
            target,
            TlsBehaviorProbeType.MALFORMED_TLS_RECORD_REJECTION,
            TlsTestVerdict.PASSED,
            "Peer rejected the malformed TLS record with a TLS alert",
            null,
            null,
            evidence);
      }
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.MALFORMED_TLS_RECORD_REJECTION,
          TlsTestVerdict.FAILED,
          "Peer responded unexpectedly to the malformed TLS record",
          null,
          null,
          evidence);
    } catch (Exception e) {
      evidence.addLogEntry(
          "Malformed-record probe triggered peer rejection: "
              + tlsClientProbeSupport.extractRootCauseMessage(e));
      return buildBehaviorReport(
          target,
          TlsBehaviorProbeType.MALFORMED_TLS_RECORD_REJECTION,
          TlsTestVerdict.PASSED,
          "Peer rejected the malformed TLS record: "
              + tlsClientProbeSupport.extractRootCauseMessage(e),
          null,
          null,
          evidence);
    }
  }

  /**
   * Scans one feature list by running the existing connectivity handshake for each token.
   *
   * @param target target endpoint to probe
   * @param features feature tokens to test
   * @param configuration base TLS client configuration
   * @param featureType scanned feature family
   * @return structured feature support report
   */
  private TlsFeatureSupportReport scanFeatures(
      TlsTestTarget target,
      List<String> features,
      TlsConnectionConfiguration configuration,
      TlsScannedFeatureType featureType) {
    if (features == null || features.isEmpty()) {
      throw new IllegalArgumentException("features must not be empty");
    }
    final List<TlsFeatureSupportResult> results =
        features.stream()
            .map(feature -> scanFeature(target, feature, configuration, featureType))
            .toList();
    return new TlsFeatureSupportReport(target, featureType, Instant.now(), results);
  }

  /**
   * Scans one feature token by running the connectivity check with a temporary override.
   *
   * @param target target endpoint to probe
   * @param feature feature token to test
   * @param configuration base TLS client configuration
   * @param featureType scanned feature family
   * @return per-feature support result
   */
  private TlsFeatureSupportResult scanFeature(
      TlsTestTarget target,
      String feature,
      TlsConnectionConfiguration configuration,
      TlsScannedFeatureType featureType) {
    if (feature == null || feature.isBlank()) {
      throw new IllegalArgumentException("feature must not be blank");
    }
    final TlsProbeEvidenceBuilder evidence =
        buildFeatureEvidence(target, configuration, featureType, feature);
    evidence.addLogEntry("Scanning feature " + feature + " of type " + featureType);
    if (featureType == TlsScannedFeatureType.NAMED_GROUP
        || featureType == TlsScannedFeatureType.SIGNATURE_SCHEME) {
      evidence.addNote(LOW_LEVEL_VALIDATION_NOTE);
      return scanLowLevelFeature(target, feature, configuration, featureType, evidence);
    }
    final TlsConnectionConfiguration effectiveConfiguration =
        featureType == TlsScannedFeatureType.PROTOCOL
            ? configuration.withEnabledProtocols(List.of(feature))
            : configuration.withEnabledCipherSuites(List.of(feature));
    final TlsTestReport report =
        tlsTestRunner.run(
            new TlsTestRequest(target, TlsTestProfile.CONNECTIVITY, effectiveConfiguration));
    final TlsTestResult handshakeResult = report.findResult(TlsTestCase.HANDSHAKE).orElseThrow();
    evidence.addLogEntry(
        "Handshake verdict for feature "
            + feature
            + ": "
            + handshakeResult.verdict()
            + " ("
            + handshakeResult.details()
            + ")");
    return new TlsFeatureSupportResult(
        feature,
        handshakeResult.verdict(),
        handshakeResult.details(),
        handshakeResult.sessionSummary(),
        evidence.build());
  }

  /**
   * Creates the reproduction evidence for one scan token.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @param featureType scanned feature family
   * @param feature scanned feature token
   * @return evidence builder seeded for the scanned feature
   */
  private TlsProbeEvidenceBuilder buildFeatureEvidence(
      TlsTestTarget target,
      TlsConnectionConfiguration configuration,
      TlsScannedFeatureType featureType,
      String feature) {
    return switch (featureType) {
      case PROTOCOL -> tlsOpenSslEvidenceFactory.forProtocolProbe(target, configuration, feature);
      case CIPHER_SUITE ->
          tlsOpenSslEvidenceFactory.forCipherSuiteProbe(target, configuration, feature);
      case NAMED_GROUP ->
          tlsOpenSslEvidenceFactory.forNamedGroupProbe(target, configuration, feature);
      case SIGNATURE_SCHEME ->
          tlsOpenSslEvidenceFactory.forSignatureSchemeProbe(target, configuration, feature);
    };
  }

  /**
   * Scans one feature token using the low-level BouncyCastle client path.
   *
   * @param target target endpoint to probe
   * @param feature feature token under test
   * @param configuration base TLS client configuration
   * @param featureType scanned feature family
   * @param evidence evidence collector updated with execution details
   * @return per-feature support result
   */
  private TlsFeatureSupportResult scanLowLevelFeature(
      TlsTestTarget target,
      String feature,
      TlsConnectionConfiguration configuration,
      TlsScannedFeatureType featureType,
      TlsProbeEvidenceBuilder evidence) {
    final LowLevelClientOptions options =
        switch (featureType) {
          case NAMED_GROUP ->
              LowLevelClientOptions.withNamedGroups(new int[] {mapNamedGroup(feature)});
          case SIGNATURE_SCHEME ->
              LowLevelClientOptions.withSignatureSchemes(new int[] {mapSignatureScheme(feature)});
          case PROTOCOL, CIPHER_SUITE ->
              throw new IllegalArgumentException(
                  "Unexpected low-level scan type for feature scan: " + featureType);
        };
    final InspectableTlsClient client = new InspectableTlsClient(target, configuration, options);
    try {
      final TlsSessionSummary sessionSummary =
          connectLowLevel(target, configuration, client, evidence);
      return new TlsFeatureSupportResult(
          feature,
          TlsTestVerdict.PASSED,
          "Low-level handshake succeeded while advertising only " + feature,
          sessionSummary,
          evidence.build());
    } catch (Exception e) {
      recordClientAlerts(client, evidence);
      return new TlsFeatureSupportResult(
          feature,
          TlsTestVerdict.FAILED,
          "Low-level handshake failed while advertising only "
              + feature
              + ": "
              + tlsClientProbeSupport.extractRootCauseMessage(e),
          null,
          evidence.build());
    }
  }

  /**
   * Forces the probe configuration to TLS 1.2 while preserving the remaining client settings.
   *
   * @param configuration base TLS client configuration
   * @return TLS 1.2-only connection configuration
   */
  private TlsConnectionConfiguration withTls12Only(TlsConnectionConfiguration configuration) {
    return configuration.withEnabledProtocols(List.of("TLSv1.2"));
  }

  /**
   * Performs one TLS 1.2 handshake while reusing an existing SSL context.
   *
   * @param target target endpoint to probe
   * @param configuration TLS connection configuration
   * @param sslContext shared SSL context used for session resumption attempts
   * @param protocol protocol token to expose to the peer
   * @return handshake attempt result containing the negotiated summary and session identifier
   * @throws Exception if the handshake fails
   */
  private HandshakeAttempt performHandshake(
      TlsTestTarget target,
      TlsConnectionConfiguration configuration,
      SSLContext sslContext,
      String protocol)
      throws Exception {
    try (SSLSocket socket =
        tlsClientProbeSupport.openSocket(
            sslContext, target, configuration, new String[] {protocol}, null)) {
      socket.startHandshake();
      final SSLSession session = socket.getSession();
      return new HandshakeAttempt(
          tlsClientProbeSupport.buildSessionSummary(session), session.getId().clone());
    }
  }

  /**
   * Opens a plain TCP socket for probes that implement the TLS handshake themselves.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @return connected plain socket
   * @throws IOException if the socket cannot be connected
   */
  private Socket openPlainSocket(TlsTestTarget target, TlsConnectionConfiguration configuration)
      throws IOException {
    final Socket socket = new Socket();
    final int timeoutMillis = (int) configuration.timeout().toMillis();
    socket.setSoTimeout(timeoutMillis);
    socket.connect(new InetSocketAddress(target.host(), target.port()), timeoutMillis);
    return socket;
  }

  /**
   * Executes one low-level BouncyCastle handshake and returns the observed session summary.
   *
   * @param target target endpoint to probe
   * @param configuration base TLS client configuration
   * @param client inspectable low-level TLS client
   * @param evidence evidence collector updated with the observed handshake output
   * @return observed session summary
   * @throws Exception if the low-level handshake fails
   */
  private TlsSessionSummary connectLowLevel(
      TlsTestTarget target,
      TlsConnectionConfiguration configuration,
      InspectableTlsClient client,
      TlsProbeEvidenceBuilder evidence)
      throws Exception {
    try (Socket socket = openPlainSocket(target, configuration)) {
      final TlsClientProtocol tlsClientProtocol =
          new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream());
      tlsClientProtocol.connect(client);
      recordClientAlerts(client, evidence);
      evidence.addLogEntry(
          "Low-level handshake negotiated "
              + client.selectedProtocolText()
              + " / "
              + client.selectedCipherSuiteText());
      return client.sessionSummary();
    }
  }

  /**
   * Adds alert-related log entries captured by the low-level client.
   *
   * @param client inspectable low-level TLS client
   * @param evidence evidence collector
   */
  private void recordClientAlerts(
      InspectableTlsClient client, TlsProbeEvidenceBuilder evidence) {
    if (client.receivedAlertDescription() != null) {
      evidence.addLogEntry("Received TLS alert " + AlertDescription.getText(client.receivedAlertDescription()));
    }
    if (client.raisedAlertDescription() != null) {
      evidence.addLogEntry("Raised TLS alert " + AlertDescription.getText(client.raisedAlertDescription()));
    }
  }

  /**
   * Creates the immutable report object and logs the final result.
   *
   * @param target probed target endpoint
   * @param probeType executed probe type
   * @param verdict final verdict
   * @param details final details
   * @param initialSessionSummary first session summary
   * @param followUpSessionSummary follow-up session summary
   * @param evidenceBuilder mutable evidence collector
   * @return immutable behavior probe report
   */
  private TlsBehaviorProbeReport buildBehaviorReport(
      TlsTestTarget target,
      TlsBehaviorProbeType probeType,
      TlsTestVerdict verdict,
      String details,
      TlsSessionSummary initialSessionSummary,
      TlsSessionSummary followUpSessionSummary,
      TlsProbeEvidenceBuilder evidenceBuilder) {
    evidenceBuilder.addLogEntry("Final verdict for " + probeType + ": " + verdict);
    LOG.info(
        "TLS probe {} against {}:{} finished with {}: {}",
        probeType,
        target.host(),
        target.port(),
        verdict,
        details);
    return new TlsBehaviorProbeReport(
        target,
        probeType,
        Instant.now(),
        verdict,
        details,
        initialSessionSummary,
        followUpSessionSummary,
        evidenceBuilder.build());
  }

  /**
   * Builds a deliberately malformed TLS record that advertises a longer handshake payload than it
   * actually contains.
   *
   * @return malformed TLS client-hello record bytes
   */
  private byte[] malformedClientHelloRecord() {
    return new byte[] {
      0x16, 0x03, 0x03, 0x00, 0x10,
      0x01, 0x00, 0x00, 0x0c,
      0x03, 0x03,
      0x00, 0x00, 0x00
    };
  }

  /**
   * Maps Java-style TLS version tokens to BouncyCastle protocol versions.
   *
   * @param protocolToken Java-style TLS version token
   * @return BouncyCastle protocol version
   */
  private ProtocolVersion mapProtocolVersion(String protocolToken) {
    return switch (protocolToken) {
      case "TLSv1.0", "TLSv1" -> ProtocolVersion.TLSv10;
      case "TLSv1.1" -> ProtocolVersion.TLSv11;
      case "TLSv1.2" -> ProtocolVersion.TLSv12;
      case "TLSv1.3" -> ProtocolVersion.TLSv13;
      default -> throw new IllegalArgumentException("Unsupported TLS protocol token: " + protocolToken);
    };
  }

  /**
   * Maps Java-style cipher-suite names to BouncyCastle cipher-suite identifiers.
   *
   * @param cipherSuiteToken Java-style cipher-suite token
   * @return BouncyCastle cipher-suite identifier
   */
  private int mapCipherSuite(String cipherSuiteToken) {
    try {
      return CipherSuite.class.getField(cipherSuiteToken).getInt(null);
    } catch (ReflectiveOperationException e) {
      throw new IllegalArgumentException("Unsupported TLS cipher suite token: " + cipherSuiteToken, e);
    }
  }

  /**
   * Maps a named-group token to a BouncyCastle named-group identifier.
   *
   * @param namedGroupToken named-group token
   * @return BouncyCastle named-group identifier
   */
  private int mapNamedGroup(String namedGroupToken) {
    try {
      return NamedGroup.class.getField(namedGroupToken).getInt(null);
    } catch (ReflectiveOperationException e) {
      throw new IllegalArgumentException("Unsupported TLS named group token: " + namedGroupToken, e);
    }
  }

  /**
   * Maps a signature-scheme token to a BouncyCastle signature-scheme identifier.
   *
   * @param signatureSchemeToken signature-scheme token
   * @return BouncyCastle signature-scheme identifier
   */
  private int mapSignatureScheme(String signatureSchemeToken) {
    try {
      return SignatureScheme.class.getField(signatureSchemeToken).getInt(null);
    } catch (ReflectiveOperationException e) {
      throw new IllegalArgumentException(
          "Unsupported TLS signature scheme token: " + signatureSchemeToken, e);
    }
  }

  /**
   * Resolves a BouncyCastle cipher-suite identifier back to a readable token.
   *
   * @param cipherSuiteId BouncyCastle cipher-suite identifier
   * @return readable cipher-suite token
   */
  private String resolveCipherSuiteName(int cipherSuiteId) {
    if (cipherSuiteId < 0) {
      return "UNKNOWN";
    }
    try {
      for (Field field : CipherSuite.class.getFields()) {
        if (field.getType() == int.class
            && Modifier.isStatic(field.getModifiers())
            && field.getInt(null) == cipherSuiteId) {
          return field.getName();
        }
      }
    } catch (IllegalAccessException e) {
      return Integer.toString(cipherSuiteId);
    }
    return Integer.toString(cipherSuiteId);
  }

  /**
   * Resolves a BouncyCastle named-group identifier back to a readable token.
   *
   * @param namedGroupId BouncyCastle named-group identifier
   * @return readable named-group token
   */
  private String resolveNamedGroupName(int namedGroupId) {
    return namedGroupId < 0 ? "UNKNOWN" : NamedGroup.getName(namedGroupId);
  }

  /**
   * Resolves a BouncyCastle signature-scheme identifier back to a readable token.
   *
   * @param signatureSchemeId BouncyCastle signature-scheme identifier
   * @return readable signature-scheme token
   */
  private String resolveSignatureSchemeName(int signatureSchemeId) {
    return signatureSchemeId < 0 ? "UNKNOWN" : SignatureScheme.getName(signatureSchemeId);
  }

  /**
   * Builds the effective protocol-version list for the low-level BouncyCastle client.
   *
   * @param configuration base TLS client configuration
   * @return effective BouncyCastle protocol-version list
   */
  private ProtocolVersion[] resolveBcProtocolVersions(TlsConnectionConfiguration configuration) {
    if (configuration.enabledProtocols().isEmpty()) {
      return null;
    }
    return configuration.enabledProtocols().stream()
        .map(this::mapProtocolVersion)
        .toArray(ProtocolVersion[]::new);
  }

  /**
   * Builds the effective cipher-suite list for the low-level BouncyCastle client.
   *
   * @param configuration base TLS client configuration
   * @return effective BouncyCastle cipher-suite list
   */
  private int[] resolveBcCipherSuites(TlsConnectionConfiguration configuration) {
    if (configuration.enabledCipherSuites().isEmpty()) {
      return null;
    }
    return configuration.enabledCipherSuites().stream().mapToInt(this::mapCipherSuite).toArray();
  }

  /**
   * Appends TLS_FALLBACK_SCSV when it is not already present.
   *
   * @param cipherSuites configured cipher-suite list
   * @return cipher-suite list containing TLS_FALLBACK_SCSV
   */
  private int[] appendFallbackScsv(int[] cipherSuites) {
    final int[] effectiveCipherSuites =
        cipherSuites == null ? new int[0] : Arrays.copyOf(cipherSuites, cipherSuites.length);
    for (int cipherSuite : effectiveCipherSuites) {
      if (cipherSuite == CipherSuite.TLS_FALLBACK_SCSV) {
        return effectiveCipherSuites;
      }
    }
    final int[] extendedCipherSuites = Arrays.copyOf(effectiveCipherSuites, effectiveCipherSuites.length + 1);
    extendedCipherSuites[effectiveCipherSuites.length] = CipherSuite.TLS_FALLBACK_SCSV;
    return extendedCipherSuites;
  }

  /**
   * Captures the observable output of one JSSE handshake attempt.
   *
   * @param sessionSummary negotiated session summary
   * @param sessionId raw TLS session identifier
   */
  private record HandshakeAttempt(TlsSessionSummary sessionSummary, byte[] sessionId) {

    /**
     * Creates a validated handshake attempt result.
     *
     * @param sessionSummary negotiated session summary
     * @param sessionId raw TLS session identifier
     */
    private HandshakeAttempt {
      if (sessionSummary == null) {
        throw new IllegalArgumentException("sessionSummary must not be null");
      }
      sessionId = sessionId == null ? new byte[0] : sessionId.clone();
    }
  }

  /**
   * Captures the low-level client feature toggles for one handshake.
   *
   * @param requestOcspStapling whether to request a stapled OCSP response
   * @param sendUnknownExtension whether to add an unknown ClientHello extension
   * @param fallbackScsv whether to signal a fallback handshake
   * @param supportedNamedGroups optional named-group override for low-level scans
   * @param supportedSignatureSchemes optional signature-scheme override for low-level scans
   */
  private record LowLevelClientOptions(
      boolean requestOcspStapling,
      boolean sendUnknownExtension,
      boolean fallbackScsv,
      int[] supportedNamedGroups,
      int[] supportedSignatureSchemes) {

    /**
     * Returns the default low-level client options.
     *
     * @return default low-level client options
     */
    private static LowLevelClientOptions defaults() {
      return new LowLevelClientOptions(false, false, false, null, null);
    }

    /**
     * Returns low-level options that request OCSP stapling.
     *
     * @return OCSP-stapling probe options
     */
    private static LowLevelClientOptions withOcspStapling() {
      return new LowLevelClientOptions(true, false, false, null, null);
    }

    /**
     * Returns low-level options that signal a fallback handshake.
     *
     * @return fallback probe options
     */
    private static LowLevelClientOptions withFallbackScsv() {
      return new LowLevelClientOptions(false, false, true, null, null);
    }

    /**
     * Returns low-level options that add an unknown ClientHello extension.
     *
     * @return unknown-extension probe options
     */
    private static LowLevelClientOptions withUnknownExtension() {
      return new LowLevelClientOptions(false, true, false, null, null);
    }

    /**
     * Returns low-level options that advertise only the supplied named groups.
     *
     * @param supportedNamedGroups named-group identifiers to advertise
     * @return named-group probe options
     */
    private static LowLevelClientOptions withNamedGroups(int[] supportedNamedGroups) {
      return new LowLevelClientOptions(
          false,
          false,
          false,
          supportedNamedGroups == null ? null : supportedNamedGroups.clone(),
          null);
    }

    /**
     * Returns low-level options that advertise only the supplied signature schemes.
     *
     * @param supportedSignatureSchemes signature-scheme identifiers to advertise
     * @return signature-scheme probe options
     */
    private static LowLevelClientOptions withSignatureSchemes(int[] supportedSignatureSchemes) {
      return new LowLevelClientOptions(
          false,
          false,
          false,
          null,
          supportedSignatureSchemes == null ? null : supportedSignatureSchemes.clone());
    }
  }

  /**
   * Low-level BouncyCastle TLS client used for probes that need direct access to handshake
   * extensions, alerts, and version-selection callbacks.
   */
  private final class InspectableTlsClient extends DefaultTlsClient {

    private final TlsTestTarget target;
    private final ProtocolVersion[] protocolVersions;
    private final int[] cipherSuites;
    private final LowLevelClientOptions options;
    private final int[] supportedNamedGroups;
    private final int[] supportedSignatureSchemes;
    private boolean ocspStaplingPresent;
    private boolean secureRenegotiationSupported;
    private boolean extendedMasterSecretSupported;
    private ProtocolVersion selectedProtocolVersion;
    private int selectedCipherSuite = -1;
    private Short receivedAlertDescription;
    private Short raisedAlertDescription;

    /**
     * Creates the low-level TLS client.
     *
     * @param target target endpoint to probe
     * @param configuration base TLS client configuration
     * @param options low-level probe options
     */
    private InspectableTlsClient(
        TlsTestTarget target,
        TlsConnectionConfiguration configuration,
        LowLevelClientOptions options) {
      super(new BcTlsCrypto());
      this.target = target;
      this.protocolVersions = resolveBcProtocolVersions(configuration);
      this.cipherSuites =
          options.fallbackScsv()
              ? appendFallbackScsv(resolveBcCipherSuites(configuration))
              : resolveBcCipherSuites(configuration);
      this.options = options;
      this.supportedNamedGroups =
          options.supportedNamedGroups() == null
              ? null
              : options.supportedNamedGroups().clone();
      this.supportedSignatureSchemes =
          options.supportedSignatureSchemes() == null
              ? null
              : options.supportedSignatureSchemes().clone();
    }

    /**
     * Returns whether the client should announce a fallback handshake.
     *
     * @return {@code true} if the fallback-SCSV signal should be sent
     */
    @Override
    public boolean isFallback() {
      return options.fallbackScsv();
    }

    /**
     * Returns the protocol-version list advertised by the low-level client.
     *
     * @return effective protocol-version list
     */
    @Override
    public ProtocolVersion[] getProtocolVersions() {
      return protocolVersions == null ? super.getProtocolVersions() : protocolVersions;
    }

    /**
     * Returns the cipher-suite list advertised by the low-level client.
     *
     * @return effective cipher-suite list
     */
    @Override
    public int[] getCipherSuites() {
      return cipherSuites == null ? super.getCipherSuites() : cipherSuites;
    }

    /**
     * Returns the configured supported-group list when a named-group scan overrides it.
     *
     * @param namedGroupRoles requested named-group roles
     * @return effective supported-group list
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    protected Vector getSupportedGroups(Vector namedGroupRoles) {
      if (supportedNamedGroups == null) {
        return super.getSupportedGroups(namedGroupRoles);
      }
      final Vector groups = new Vector(supportedNamedGroups.length);
      for (int supportedNamedGroup : supportedNamedGroups) {
        groups.add(Integer.valueOf(supportedNamedGroup));
      }
      return groups;
    }

    /**
     * Returns the configured signature-algorithm list when a signature-scheme scan overrides it.
     *
     * @return effective signature-algorithm list
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    protected Vector getSupportedSignatureAlgorithms() {
      if (supportedSignatureSchemes == null) {
        return super.getSupportedSignatureAlgorithms();
      }
      final Vector algorithms = new Vector(supportedSignatureSchemes.length);
      for (int supportedSignatureScheme : supportedSignatureSchemes) {
        final SignatureAndHashAlgorithm algorithm =
            SignatureScheme.getSignatureAndHashAlgorithm(supportedSignatureScheme);
        if (algorithm != null) {
          algorithms.add(algorithm);
        }
      }
      return algorithms;
    }

    /**
     * Requests an OCSP staple when the probe requires it.
     *
     * @return OCSP status request or {@code null}
     */
    @Override
    protected CertificateStatusRequest getCertificateStatusRequest() {
      if (!options.requestOcspStapling()) {
        return null;
      }
      return new CertificateStatusRequest(
          CertificateStatusType.ocsp, new OCSPStatusRequest(new Vector(), null));
    }

    /**
     * Supplies the configured SNI host name when one is appropriate.
     *
     * @return SNI server-name list or {@code null}
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    protected Vector getSNIServerNames() {
      if (target.effectiveSniHostName().isBlank()
          || target.effectiveSniHostName().equals(target.host())
              && target.host().matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
        return null;
      }
      final Vector serverNames = new Vector(1);
      serverNames.add(
          new ServerName(
              NameType.host_name,
              target.effectiveSniHostName().getBytes(StandardCharsets.US_ASCII)));
      return serverNames;
    }

    /**
     * Adds custom ClientHello extensions required by the probe.
     *
     * @return client extension map
     * @throws IOException if the extension map cannot be constructed
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public Hashtable getClientExtensions() throws IOException {
      Hashtable clientExtensions = super.getClientExtensions();
      clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(clientExtensions);
      if (supportedNamedGroups != null) {
        TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedNamedGroups);
        TlsExtensionsUtils.addSupportedPointFormatsExtension(
            clientExtensions, new short[] {ECPointFormat.uncompressed});
      }
      if (supportedSignatureSchemes != null) {
        TlsExtensionsUtils.addSignatureAlgorithmsExtension(
            clientExtensions, getSupportedSignatureAlgorithms());
      }
      if (options.sendUnknownExtension()) {
        clientExtensions.put(Integer.valueOf(UNKNOWN_EXTENSION_TYPE), new byte[] {0x00, 0x01});
      }
      return clientExtensions;
    }

    /**
     * Captures whether secure renegotiation was advertised by the peer.
     *
     * @param secureRenegotiation secure renegotiation indicator
     * @throws IOException if the handshake processing fails
     */
    @Override
    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException {
      super.notifySecureRenegotiation(secureRenegotiation);
      secureRenegotiationSupported = secureRenegotiation;
    }

    /**
     * Captures the negotiated server protocol version.
     *
     * @param serverVersion negotiated server protocol version
     * @throws IOException if the handshake processing fails
     */
    @Override
    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
      super.notifyServerVersion(serverVersion);
      selectedProtocolVersion = serverVersion;
    }

    /**
     * Captures the negotiated cipher suite.
     *
     * @param selectedCipherSuite negotiated cipher-suite identifier
     */
    @Override
    public void notifySelectedCipherSuite(int selectedCipherSuite) {
      super.notifySelectedCipherSuite(selectedCipherSuite);
      this.selectedCipherSuite = selectedCipherSuite;
    }

    /**
     * Captures negotiated server extensions for feature probes.
     *
     * @param serverExtensions negotiated server extensions
     * @throws IOException if the extensions cannot be processed
     */
    @SuppressWarnings("rawtypes")
    @Override
    public void processServerExtensions(Hashtable serverExtensions) throws IOException {
      super.processServerExtensions(serverExtensions);
      extendedMasterSecretSupported =
          serverExtensions != null
              && TlsExtensionsUtils.hasExtendedMasterSecretExtension(serverExtensions);
    }

    /**
     * Supplies authentication callbacks for server-certificate inspection.
     *
     * @return authentication callbacks
     */
    @Override
    public TlsAuthentication getAuthentication() {
      return new TlsAuthentication() {

        /**
         * Captures whether the peer returned an OCSP staple.
         *
         * @param serverCertificate server certificate container
         */
        @Override
        public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
          ocspStaplingPresent = serverCertificate.getCertificateStatus() != null;
        }

        /**
         * Disables client-certificate authentication for this low-level probe path.
         *
         * @param certificateRequest server certificate request
         * @return never returns client credentials
         */
        @Override
        public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
          return null;
        }
      };
    }

    /**
     * Captures alerts raised by the client during the handshake.
     *
     * @param alertLevel TLS alert level
     * @param alertDescription TLS alert description
     * @param message alert message
     * @param cause alert cause
     */
    @Override
    public void notifyAlertRaised(
        short alertLevel, short alertDescription, String message, Throwable cause) {
      super.notifyAlertRaised(alertLevel, alertDescription, message, cause);
      raisedAlertDescription = alertDescription;
    }

    /**
     * Captures alerts received from the server during the handshake.
     *
     * @param alertLevel TLS alert level
     * @param alertDescription TLS alert description
     */
    @Override
    public void notifyAlertReceived(short alertLevel, short alertDescription) {
      super.notifyAlertReceived(alertLevel, alertDescription);
      receivedAlertDescription = alertDescription;
    }

    /**
     * Returns whether an OCSP staple was observed in the handshake.
     *
     * @return {@code true} if a staple was observed
     */
    private boolean ocspStaplingPresent() {
      return ocspStaplingPresent;
    }

    /**
     * Returns whether secure renegotiation was advertised by the peer.
     *
     * @return {@code true} if secure renegotiation was advertised
     */
    private boolean secureRenegotiationSupported() {
      return secureRenegotiationSupported;
    }

    /**
     * Returns whether the extended-master-secret extension was negotiated.
     *
     * @return {@code true} if extended master secret was negotiated
     */
    private boolean extendedMasterSecretSupported() {
      return extendedMasterSecretSupported;
    }

    /**
     * Returns the last TLS alert received from the peer, when present.
     *
     * @return last received alert description
     */
    private Short receivedAlertDescription() {
      return receivedAlertDescription;
    }

    /**
     * Returns the last TLS alert raised by the client, when present.
     *
     * @return last raised alert description
     */
    private Short raisedAlertDescription() {
      return raisedAlertDescription;
    }

    /**
     * Returns the negotiated protocol text or {@code UNKNOWN}.
     *
     * @return negotiated protocol text
     */
    private String selectedProtocolText() {
      return selectedProtocolVersion == null ? "UNKNOWN" : selectedProtocolVersion.toString();
    }

    /**
     * Returns the negotiated cipher-suite text or {@code UNKNOWN}.
     *
     * @return negotiated cipher-suite text
     */
    private String selectedCipherSuiteText() {
      return resolveCipherSuiteName(selectedCipherSuite);
    }

    /**
     * Builds a simplified session summary from the low-level handshake output.
     *
     * @return simplified session summary
     */
    private TlsSessionSummary sessionSummary() {
      return new TlsSessionSummary(selectedProtocolText(), selectedCipherSuiteText(), List.of());
    }
  }
}
