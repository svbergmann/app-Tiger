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

import java.net.SocketException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Starts one-shot TLS observation servers that let Tiger accept one client connection and inspect
 * the negotiated result.
 */
public class TlsServerObservationRunner {

  private static final Logger LOG = LoggerFactory.getLogger(TlsServerObservationRunner.class);

  private final TlsServerProbeSupport tlsServerProbeSupport;
  private final TlsOpenSslEvidenceFactory tlsOpenSslEvidenceFactory;

  /**
   * Creates the runner with the default probe helpers.
   */
  public TlsServerObservationRunner() {
    this(new TlsServerProbeSupport(), new TlsOpenSslEvidenceFactory());
  }

  /**
   * Creates the runner with injectable collaborators.
   *
   * @param tlsServerProbeSupport server-side probe helper
   * @param tlsOpenSslEvidenceFactory factory for OpenSSL reproduction evidence
   */
  TlsServerObservationRunner(
      TlsServerProbeSupport tlsServerProbeSupport,
      TlsOpenSslEvidenceFactory tlsOpenSslEvidenceFactory) {
    this.tlsServerProbeSupport = tlsServerProbeSupport;
    this.tlsOpenSslEvidenceFactory = tlsOpenSslEvidenceFactory;
  }

  /**
   * Starts a one-shot TLS observation server on the requested port.
   *
   * @param port requested local TCP port, or {@code 0} for an ephemeral port
   * @param configuration server-side TLS observation configuration
   * @return handle for the running observation server
   * @throws Exception if the observation server cannot be started
   */
  public TlsServerObservationHandle start(int port, TlsServerConnectionConfiguration configuration)
      throws Exception {
    if (port < 0 || port > 65535) {
      throw new IllegalArgumentException("port must be between 0 and 65535");
    }
    final SSLContext sslContext = tlsServerProbeSupport.buildSslContext(configuration);
    final SSLServerSocket serverSocket =
        tlsServerProbeSupport.openServerSocket(sslContext, port, configuration);
    final String bindHost = tlsServerProbeSupport.resolveBindAddress(serverSocket);
    final int boundPort = serverSocket.getLocalPort();
    final CompletableFuture<TlsServerObservationReport> observationFuture =
        new CompletableFuture<>();
    final ExecutorService executorService = Executors.newSingleThreadExecutor();

    LOG.info("Started TLS observation server on {}:{}", bindHost, boundPort);
    executorService.submit(
        () -> acceptOneConnection(serverSocket, configuration, observationFuture, bindHost, boundPort));

    return new TlsServerObservationHandle(
        bindHost,
        boundPort,
        configuration.timeout(),
        observationFuture,
        () -> closeResources(serverSocket, executorService));
  }

  /**
   * Accepts one TLS client connection and completes the observation result.
   *
   * @param serverSocket running observation server socket
   * @param configuration server-side TLS observation configuration
   * @param observationFuture future completed with the observation result
   * @param bindHost local bind host of the observation server
   * @param port local port of the observation server
   */
  private void acceptOneConnection(
      SSLServerSocket serverSocket,
      TlsServerConnectionConfiguration configuration,
      CompletableFuture<TlsServerObservationReport> observationFuture,
      String bindHost,
      int port) {
    final TlsProbeEvidenceBuilder evidence =
        tlsOpenSslEvidenceFactory.forServerObservation(bindHost, port, configuration);
    final List<String> observedServerNames = new ArrayList<>();
    String remoteAddress = null;
    evidence.addLogEntry("Waiting for one TLS client connection");
    try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
      remoteAddress = String.valueOf(socket.getRemoteSocketAddress());
      tlsServerProbeSupport.applyAcceptedSocketConfiguration(
          socket, configuration, observedServerNames);
      evidence.addLogEntry("Accepted TLS client connection from " + remoteAddress);
      socket.startHandshake();

      final TlsServerObservationReport report =
          buildSuccessfulReport(
              socket, configuration, bindHost, port, remoteAddress, observedServerNames, evidence);
      observationFuture.complete(report);
    } catch (SocketException e) {
      final String message = tlsServerProbeSupport.extractRootCauseMessage(e);
      if (!serverSocket.isClosed()) {
        observationFuture.complete(
            buildFailedReport(bindHost, port, message, remoteAddress, evidence));
      }
    } catch (Exception e) {
      observationFuture.complete(
          buildFailedReport(
              bindHost,
              port,
              tlsServerProbeSupport.extractRootCauseMessage(e),
              remoteAddress,
              evidence));
    } finally {
      closeQuietly(serverSocket);
    }
  }

  /**
   * Builds the successful observation report after one completed handshake.
   *
   * @param socket accepted TLS socket
   * @param configuration server-side TLS observation configuration
   * @param bindHost local bind host of the observation server
   * @param port local port of the observation server
   * @param remoteAddress remote client socket address
   * @param observedServerNames SNI names captured during the handshake
   * @param evidence evidence collector updated with handshake details
   * @return completed server-side TLS observation report
   */
  private TlsServerObservationReport buildSuccessfulReport(
      SSLSocket socket,
      TlsServerConnectionConfiguration configuration,
      String bindHost,
      int port,
      String remoteAddress,
      List<String> observedServerNames,
      TlsProbeEvidenceBuilder evidence) {
    final var session = socket.getSession();
    final TlsSessionSummary sessionSummary = tlsServerProbeSupport.buildSessionSummary(session);
    final String negotiatedApplicationProtocol = negotiatedApplicationProtocol(socket);
    final List<String> requestedServerNames =
        observedServerNames.isEmpty()
            ? tlsServerProbeSupport.extractRequestedServerNames(session)
            : List.copyOf(observedServerNames);
    final var clientCertificateSubjects =
        tlsServerProbeSupport.extractPeerCertificateSubjects(session);

    evidence.addLogEntry(
        "Negotiated TLS server-side handshake "
            + sessionSummary.negotiatedProtocol()
            + " / "
            + sessionSummary.negotiatedCipherSuite());
    if (negotiatedApplicationProtocol != null) {
      evidence.addLogEntry("Negotiated ALPN application protocol " + negotiatedApplicationProtocol);
    }
    if (!requestedServerNames.isEmpty()) {
      evidence.addLogEntry("Observed requested SNI names " + requestedServerNames);
    }
    if (!clientCertificateSubjects.isEmpty()) {
      evidence.addLogEntry("Observed client certificates " + clientCertificateSubjects);
    } else if (configuration.requireClientCertificate()) {
      evidence.addLogEntry("Client certificate requirement was enabled and the handshake succeeded");
    }

    return new TlsServerObservationReport(
        bindHost,
        port,
        Instant.now(),
        TlsTestVerdict.PASSED,
        "Observed one TLS client connection with "
            + sessionSummary.negotiatedProtocol()
            + " and "
            + sessionSummary.negotiatedCipherSuite(),
        sessionSummary,
        negotiatedApplicationProtocol,
        requestedServerNames,
        clientCertificateSubjects,
        remoteAddress,
        evidence.build());
  }

  /**
   * Returns the negotiated ALPN application protocol when the runtime exposes one.
   *
   * @param socket accepted TLS socket
   * @return negotiated ALPN application protocol, or {@code null}
   */
  private String negotiatedApplicationProtocol(SSLSocket socket) {
    try {
      final String applicationProtocol = socket.getApplicationProtocol();
      return applicationProtocol == null || applicationProtocol.isBlank()
          ? null
          : applicationProtocol;
    } catch (UnsupportedOperationException e) {
      return null;
    }
  }

  /**
   * Builds the failed observation report for one accept or handshake failure.
   *
   * @param bindHost local bind host of the observation server
   * @param port local port of the observation server
   * @param message failure message
   * @param remoteAddress remote client socket address when available
   * @param evidence evidence collector updated with failure details
   * @return failed server-side TLS observation report
   */
  private TlsServerObservationReport buildFailedReport(
      String bindHost,
      int port,
      String message,
      String remoteAddress,
      TlsProbeEvidenceBuilder evidence) {
    evidence.addLogEntry("TLS observation failed with " + message);
    return new TlsServerObservationReport(
        bindHost,
        port,
        Instant.now(),
        TlsTestVerdict.FAILED,
        "TLS observation failed: " + message,
        null,
        null,
        java.util.List.of(),
        java.util.List.of(),
        remoteAddress,
        evidence.build());
  }

  /**
   * Closes the running observation server resources.
   *
   * @param serverSocket running observation server socket
   * @param executorService executor used for accepting the one client connection
   * @throws Exception if the resources cannot be closed cleanly
   */
  private void closeResources(SSLServerSocket serverSocket, ExecutorService executorService)
      throws Exception {
    closeQuietly(serverSocket);
    executorService.shutdownNow();
  }

  /**
   * Closes one server socket while suppressing secondary close exceptions.
   *
   * @param serverSocket server socket to close
   */
  private void closeQuietly(SSLServerSocket serverSocket) {
    try {
      serverSocket.close();
    } catch (Exception ignored) {
      // Closing a one-shot observation server is best-effort because the report outcome is more
      // important than propagating secondary close failures.
    }
  }
}
