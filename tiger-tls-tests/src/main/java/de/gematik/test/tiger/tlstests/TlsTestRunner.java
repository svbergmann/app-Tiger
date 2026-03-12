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

import de.gematik.test.tiger.common.pki.TigerConfigurationPkiIdentity;
import de.gematik.test.tiger.common.pki.TigerPkiIdentity;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** Executes a small set of active TLS checks against a configured target endpoint. */
public class TlsTestRunner {

  private static final String IN_MEMORY_KEYSTORE_PASSWORD = "changeit";

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

  private TlsTestResult execute(
      TlsTestCase testCase, TlsTestRequest request, Map<HandshakeKey, ProbeResult> probeCache) {
    return switch (testCase) {
      case HANDSHAKE -> buildHandshakeResult(getProbeResult(request, probeCache, null), testCase);
      case SUPPORTS_TLS_1_2 ->
          buildHandshakeResult(
              getProbeResult(request, probeCache, new String[] {"TLSv1.2"}), testCase);
      case SUPPORTS_TLS_1_3 ->
          buildHandshakeResult(
              getProbeResult(request, probeCache, new String[] {"TLSv1.3"}), testCase);
      case PRESENTS_CERTIFICATE ->
          buildCertificatePresenceResult(getProbeResult(request, probeCache, null));
      case CERTIFICATE_CURRENTLY_VALID ->
          buildCertificateValidityResult(getProbeResult(request, probeCache, null));
    };
  }

  private ProbeResult getProbeResult(
      TlsTestRequest request, Map<HandshakeKey, ProbeResult> probeCache, String[] enabledProtocols) {
    final HandshakeKey key = new HandshakeKey(request, enabledProtocols);
    return probeCache.computeIfAbsent(key, ignored -> probe(request, enabledProtocols));
  }

  private ProbeResult probe(TlsTestRequest request, String[] enabledProtocols) {
    try {
      final SSLContext sslContext = buildSslContext(request.connectionConfiguration());
      try (SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket()) {
        final int timeoutMillis = (int) request.connectionConfiguration().timeout().toMillis();
        socket.setSoTimeout(timeoutMillis);
        socket.connect(
            new InetSocketAddress(request.target().host(), request.target().port()), timeoutMillis);

        final SSLParameters sslParameters = socket.getSSLParameters();
        if (enabledProtocols != null) {
          sslParameters.setProtocols(enabledProtocols);
        }
        if (request.connectionConfiguration().hostnameVerification()) {
          sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
        }
        if (!request.target().effectiveSniHostName().isBlank()
            && !isIpAddress(request.target().effectiveSniHostName())) {
          sslParameters.setServerNames(
              List.of(new SNIHostName(request.target().effectiveSniHostName())));
        }
        socket.setSSLParameters(sslParameters);

        socket.startHandshake();

        final SSLSession session = socket.getSession();
        final List<X509Certificate> peerCertificates = extractPeerCertificates(session);
        return ProbeResult.success(
            new TlsSessionSummary(
                session.getProtocol(),
                session.getCipherSuite(),
                peerCertificates.stream()
                    .map(cert -> cert.getSubjectX500Principal().getName())
                    .toList()),
            peerCertificates);
      }
    } catch (Exception e) {
      return ProbeResult.failure(extractRootCauseMessage(e));
    }
  }

  private TlsTestResult buildHandshakeResult(ProbeResult probeResult, TlsTestCase testCase) {
    if (!probeResult.successful()) {
      return new TlsTestResult(
          testCase,
          TlsTestVerdict.FAILED,
          "Handshake failed: " + probeResult.failureMessage(),
          null);
    }

    final TlsSessionSummary summary = probeResult.sessionSummary();
    return new TlsTestResult(
        testCase,
        TlsTestVerdict.PASSED,
        "Handshake succeeded with %s and %s"
            .formatted(summary.negotiatedProtocol(), summary.negotiatedCipherSuite()),
        summary);
  }

  private TlsTestResult buildCertificatePresenceResult(ProbeResult probeResult) {
    if (!probeResult.successful()) {
      return new TlsTestResult(
          TlsTestCase.PRESENTS_CERTIFICATE,
          TlsTestVerdict.FAILED,
          "Could not inspect certificates because the handshake failed: "
              + probeResult.failureMessage(),
          null);
    }

    if (probeResult.peerCertificates().isEmpty()) {
      return new TlsTestResult(
          TlsTestCase.PRESENTS_CERTIFICATE,
          TlsTestVerdict.FAILED,
          "Handshake succeeded but the peer did not present any certificate",
          probeResult.sessionSummary());
    }

    return new TlsTestResult(
        TlsTestCase.PRESENTS_CERTIFICATE,
        TlsTestVerdict.PASSED,
        "Peer presented %d certificate(s)".formatted(probeResult.peerCertificates().size()),
        probeResult.sessionSummary());
  }

  private TlsTestResult buildCertificateValidityResult(ProbeResult probeResult) {
    if (!probeResult.successful()) {
      return new TlsTestResult(
          TlsTestCase.CERTIFICATE_CURRENTLY_VALID,
          TlsTestVerdict.FAILED,
          "Could not validate certificate dates because the handshake failed: "
              + probeResult.failureMessage(),
          null);
    }

    if (probeResult.peerCertificates().isEmpty()) {
      return new TlsTestResult(
          TlsTestCase.CERTIFICATE_CURRENTLY_VALID,
          TlsTestVerdict.FAILED,
          "Handshake succeeded but no peer certificate was available for validity checks",
          probeResult.sessionSummary());
    }

    try {
      final Date now = new Date();
      for (X509Certificate certificate : probeResult.peerCertificates()) {
        certificate.checkValidity(now);
      }
      return new TlsTestResult(
          TlsTestCase.CERTIFICATE_CURRENTLY_VALID,
          TlsTestVerdict.PASSED,
          "All presented certificates are currently valid",
          probeResult.sessionSummary());
    } catch (Exception e) {
      return new TlsTestResult(
          TlsTestCase.CERTIFICATE_CURRENTLY_VALID,
          TlsTestVerdict.FAILED,
          "Certificate validity check failed: " + extractRootCauseMessage(e),
          probeResult.sessionSummary());
    }
  }

  private SSLContext buildSslContext(TlsConnectionConfiguration configuration) throws Exception {
    final SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(
        buildKeyManagers(configuration.clientIdentity()),
        buildTrustManagers(configuration),
        new SecureRandom());
    return sslContext;
  }

  private KeyManager[] buildKeyManagers(TigerConfigurationPkiIdentity clientIdentity)
      throws Exception {
    if (clientIdentity == null) {
      return null;
    }

    final TigerPkiIdentity identity =
        new TigerPkiIdentity(clientIdentity.getFileLoadingInformation());
    final KeyStore keyStore = identity.toKeyStoreWithPassword(IN_MEMORY_KEYSTORE_PASSWORD);
    final KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, IN_MEMORY_KEYSTORE_PASSWORD.toCharArray());
    return keyManagerFactory.getKeyManagers();
  }

  private TrustManager[] buildTrustManagers(TlsConnectionConfiguration configuration)
      throws Exception {
    if (configuration.trustAllCertificates()) {
      return new TrustManager[] {new TrustAllX509TrustManager()};
    }

    if (configuration.trustStoreIdentity() != null) {
      final TigerPkiIdentity trustIdentity =
          new TigerPkiIdentity(configuration.trustStoreIdentity().getFileLoadingInformation());
      final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
      trustStore.load(null, null);
      int entryCounter = 0;
      for (Certificate certificate : trustIdentity.buildChainWithCertificate()) {
        trustStore.setCertificateEntry("trusted-%d".formatted(entryCounter++), certificate);
      }
      final TrustManagerFactory trustManagerFactory =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init(trustStore);
      return trustManagerFactory.getTrustManagers();
    }

    return null;
  }

  private List<X509Certificate> extractPeerCertificates(SSLSession session) throws Exception {
    final List<X509Certificate> certificates = new ArrayList<>();
    for (Certificate certificate : session.getPeerCertificates()) {
      certificates.add((X509Certificate) certificate);
    }
    return certificates;
  }

  private boolean isIpAddress(String hostname) {
    try {
      return hostname.equals(InetAddress.getByName(hostname).getHostAddress());
    } catch (Exception e) {
      return false;
    }
  }

  private String extractRootCauseMessage(Throwable throwable) {
    Throwable current = throwable;
    while (current.getCause() != null) {
      current = current.getCause();
    }
    return current.getMessage() == null ? current.getClass().getSimpleName() : current.getMessage();
  }

  private record HandshakeKey(TlsTestRequest request, List<String> enabledProtocols) {
    private HandshakeKey(TlsTestRequest request, String[] enabledProtocols) {
      this(request, enabledProtocols == null ? List.of() : List.of(enabledProtocols));
    }
  }

  private record ProbeResult(
      boolean successful,
      String failureMessage,
      TlsSessionSummary sessionSummary,
      List<X509Certificate> peerCertificates) {

    private static ProbeResult success(
        TlsSessionSummary sessionSummary, List<X509Certificate> peerCertificates) {
      return new ProbeResult(true, null, sessionSummary, List.copyOf(peerCertificates));
    }

    private static ProbeResult failure(String failureMessage) {
      return new ProbeResult(false, failureMessage, null, List.of());
    }
  }

  private static final class TrustAllX509TrustManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}
