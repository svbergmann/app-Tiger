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
package de.gematik.test.tiger.glue;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.test.tiger.common.config.ConfigurationValuePrecedence;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.test.tiger.common.pki.TigerConfigurationPkiIdentity;
import de.gematik.test.tiger.common.util.TigerSerializationUtil;
import de.gematik.test.tiger.tlstests.TlsBehaviorProbeReport;
import de.gematik.test.tiger.tlstests.TlsComplianceRunner;
import de.gematik.test.tiger.tlstests.TlsConnectionConfiguration;
import de.gematik.test.tiger.tlstests.TlsFeatureSupportReport;
import de.gematik.test.tiger.tlstests.TlsFeatureSupportResult;
import de.gematik.test.tiger.tlstests.TlsServerConnectionConfiguration;
import de.gematik.test.tiger.tlstests.TlsServerObservationHandle;
import de.gematik.test.tiger.tlstests.TlsServerObservationReport;
import de.gematik.test.tiger.tlstests.TlsServerObservationRunner;
import de.gematik.test.tiger.tlstests.TlsTestCase;
import de.gematik.test.tiger.tlstests.TlsTestProfile;
import de.gematik.test.tiger.tlstests.TlsTestReport;
import de.gematik.test.tiger.tlstests.TlsTestRequest;
import de.gematik.test.tiger.tlstests.TlsTestRunner;
import de.gematik.test.tiger.tlstests.TlsTestTarget;
import de.gematik.test.tiger.tlstests.TlsTestVerdict;
import io.cucumber.java.de.Dann;
import io.cucumber.java.de.Wenn;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.function.UnaryOperator;
import lombok.extern.slf4j.Slf4j;

/** TGR glue for running the built-in TLS test profiles against remote endpoints. */
@Slf4j
public class TigerTlsTestsGlue {

  private final TlsTestRunner tlsTestRunner;
  private final TlsComplianceRunner tlsComplianceRunner;
  private final TlsServerObservationRunner tlsServerObservationRunner;
  private TlsTestReport lastTlsTestReport;
  private TlsFeatureSupportReport lastTlsProtocolScanReport;
  private TlsFeatureSupportReport lastTlsCipherSuiteScanReport;
  private TlsFeatureSupportReport lastTlsApplicationProtocolScanReport;
  private TlsFeatureSupportReport lastTlsNamedGroupScanReport;
  private TlsFeatureSupportReport lastTlsSignatureSchemeScanReport;
  private TlsBehaviorProbeReport lastTlsBehaviorProbeReport;
  private TlsServerObservationHandle lastTlsServerObservationHandle;
  private TlsServerObservationReport lastTlsServerObservationReport;
  private TlsConnectionConfiguration tlsConnectionConfiguration;
  private TlsServerConnectionConfiguration tlsServerConnectionConfiguration;
  private String configuredSniHostName;

  /**
   * Creates the TLS glue with default runner implementations.
   */
  public TigerTlsTestsGlue() {
    this(new TlsTestRunner(), new TlsComplianceRunner(), new TlsServerObservationRunner());
  }

  /**
   * Creates the TLS glue with an injectable profile runner and the default compliance runner.
   *
   * @param tlsTestRunner profile runner used for built-in profile execution
   */
  TigerTlsTestsGlue(TlsTestRunner tlsTestRunner) {
    this(tlsTestRunner, new TlsComplianceRunner(), new TlsServerObservationRunner());
  }

  /**
   * Creates the TLS glue with injectable profile and compliance runners and the default
   * server-observation runner.
   *
   * @param tlsTestRunner profile runner used for built-in profile execution
   * @param tlsComplianceRunner compliance runner used for scans and behavior probes
   */
  TigerTlsTestsGlue(TlsTestRunner tlsTestRunner, TlsComplianceRunner tlsComplianceRunner) {
    this(tlsTestRunner, tlsComplianceRunner, new TlsServerObservationRunner());
  }

  /**
   * Creates the TLS glue with injectable runners.
   *
   * @param tlsTestRunner profile runner used for built-in profile execution
   * @param tlsComplianceRunner compliance runner used for scans and behavior probes
   * @param tlsServerObservationRunner runner used for server-side TLS observations
   */
  TigerTlsTestsGlue(
      TlsTestRunner tlsTestRunner,
      TlsComplianceRunner tlsComplianceRunner,
      TlsServerObservationRunner tlsServerObservationRunner) {
    this.tlsTestRunner = tlsTestRunner;
    this.tlsComplianceRunner = tlsComplianceRunner;
    this.tlsServerObservationRunner = tlsServerObservationRunner;
    resetExecutionConfiguration();
  }

  /** Resets TLS-specific execution settings to their permissive defaults. */
  @Wenn("TGR setze TLS-Testkonfiguration zurück")
  @When("TGR reset TLS test configuration")
  public void resetTlsTestConfiguration() {
    resetExecutionConfiguration();
  }

  /** Enables the permissive trust-all mode for subsequent TLS test runs. */
  @Wenn("TGR aktiviere TLS trust-all Zertifikatsmodus")
  @When("TGR enable TLS trust-all certificate mode")
  public void enableTlsTrustAllCertificates() {
    updateConnectionConfiguration(current -> current.withTrustAllCertificates(true));
  }

  /** Disables the permissive trust-all mode for subsequent TLS test runs. */
  @Wenn("TGR deaktiviere TLS trust-all Zertifikatsmodus")
  @When("TGR disable TLS trust-all certificate mode")
  public void disableTlsTrustAllCertificates() {
    updateConnectionConfiguration(current -> current.withTrustAllCertificates(false));
  }

  /** Enables hostname verification for subsequent TLS test runs. */
  @Wenn("TGR aktiviere TLS Hostname-Verifikation")
  @When("TGR enable TLS hostname verification")
  public void enableTlsHostnameVerification() {
    updateConnectionConfiguration(current -> current.withHostnameVerification(true));
  }

  /** Disables hostname verification for subsequent TLS test runs. */
  @Wenn("TGR deaktiviere TLS Hostname-Verifikation")
  @When("TGR disable TLS hostname verification")
  public void disableTlsHostnameVerification() {
    updateConnectionConfiguration(current -> current.withHostnameVerification(false));
  }

  /**
   * Configures the trust store identity used by subsequent TLS test runs.
   *
   * @param identityToken PKI identity token in Tiger compact format
   */
  @Wenn("TGR setze TLS Truststore-Identity auf {tigerResolvedString}")
  @When("TGR set TLS trust store identity to {tigerResolvedString}")
  public void setTlsTrustStoreIdentity(String identityToken) {
    final TigerConfigurationPkiIdentity trustStoreIdentity =
        new TigerConfigurationPkiIdentity(identityToken);
    updateConnectionConfiguration(current -> current.withTrustStoreIdentity(trustStoreIdentity));
  }

  /** Clears the configured trust store identity for subsequent TLS test runs. */
  @Wenn("TGR entferne TLS Truststore-Identity")
  @When("TGR clear TLS trust store identity")
  public void clearTlsTrustStoreIdentity() {
    updateConnectionConfiguration(current -> current.withTrustStoreIdentity(null));
  }

  /**
   * Configures the client identity used by subsequent TLS test runs.
   *
   * @param identityToken PKI identity token in Tiger compact format
   */
  @Wenn("TGR setze TLS Client-Identity auf {tigerResolvedString}")
  @When("TGR set TLS client identity to {tigerResolvedString}")
  public void setTlsClientIdentity(String identityToken) {
    final TigerConfigurationPkiIdentity clientIdentity =
        new TigerConfigurationPkiIdentity(identityToken);
    updateConnectionConfiguration(current -> current.withClientIdentity(clientIdentity));
  }

  /** Clears the configured client identity for subsequent TLS test runs. */
  @Wenn("TGR entferne TLS Client-Identity")
  @When("TGR clear TLS client identity")
  public void clearTlsClientIdentity() {
    updateConnectionConfiguration(current -> current.withClientIdentity(null));
  }

  /**
   * Configures the timeout used by subsequent TLS test runs.
   *
   * @param timeoutSeconds timeout in seconds
   */
  @Wenn("TGR setze TLS Timeout auf {int} Sekunden")
  @When("TGR set TLS timeout to {int} seconds")
  public void setTlsTimeoutInSeconds(int timeoutSeconds) {
    updateConnectionConfiguration(current -> current.withTimeout(Duration.ofSeconds(timeoutSeconds)));
  }

  /**
   * Configures the TLS protocol versions exposed by subsequent TLS test runs.
   *
   * @param protocolTokens comma-separated protocol list such as {@code TLSv1.2, TLSv1.3}
   */
  @Wenn("TGR setze TLS Protokolle auf {tigerResolvedString}")
  @When("TGR set TLS protocols to {tigerResolvedString}")
  public void setTlsEnabledProtocols(String protocolTokens) {
    updateConnectionConfiguration(
        current -> current.withEnabledProtocols(parseTokenList(protocolTokens, "TLS protocols")));
  }

  /** Clears any configured TLS protocol restrictions for subsequent TLS test runs. */
  @Wenn("TGR entferne TLS Protokollbeschränkung")
  @When("TGR clear TLS protocol restriction")
  public void clearTlsEnabledProtocols() {
    updateConnectionConfiguration(current -> current.withEnabledProtocols(List.of()));
  }

  /**
   * Configures the TLS cipher suites exposed by subsequent TLS test runs.
   *
   * @param cipherSuiteTokens comma-separated cipher suite list
   */
  @Wenn("TGR setze TLS Cipher Suites auf {tigerResolvedString}")
  @When("TGR set TLS cipher suites to {tigerResolvedString}")
  public void setTlsEnabledCipherSuites(String cipherSuiteTokens) {
    updateConnectionConfiguration(
        current ->
            current.withEnabledCipherSuites(
                parseTokenList(cipherSuiteTokens, "TLS cipher suites")));
  }

  /** Clears any configured TLS cipher suite restrictions for subsequent TLS test runs. */
  @Wenn("TGR entferne TLS Cipher-Suite-Beschränkung")
  @When("TGR clear TLS cipher suite restriction")
  public void clearTlsEnabledCipherSuites() {
    updateConnectionConfiguration(current -> current.withEnabledCipherSuites(List.of()));
  }

  /**
   * Configures the SNI host name used by subsequent TLS test runs.
   *
   * @param sniHostName SNI host name to send during the handshake
   */
  @Wenn("TGR setze TLS SNI Host auf {tigerResolvedString}")
  @When("TGR set TLS SNI host to {tigerResolvedString}")
  public void setTlsSniHostName(String sniHostName) {
    if (sniHostName == null || sniHostName.isBlank()) {
      throw new TigerTlsTestsGlueException("TLS SNI host must not be blank");
    }
    configuredSniHostName = sniHostName;
  }

  /** Clears the configured SNI host name for subsequent TLS test runs. */
  @Wenn("TGR entferne TLS SNI Host")
  @When("TGR clear TLS SNI host")
  public void clearTlsSniHostName() {
    configuredSniHostName = null;
  }

  /** Resets TLS server-observation settings to their defaults. */
  @Wenn("TGR setze TLS-Server-Observation-Konfiguration zurück")
  @When("TGR reset TLS server observation configuration")
  public void resetTlsServerObservationConfiguration() {
    closeLastObservationHandleQuietly();
    lastTlsServerObservationReport = null;
    tlsServerConnectionConfiguration = TlsServerConnectionConfiguration.defaults();
  }

  /**
   * Configures the server identity used by subsequent TLS server observations.
   *
   * @param identityToken PKI identity token in Tiger compact format
   */
  @Wenn("TGR setze TLS-Server-Identity auf {tigerResolvedString}")
  @When("TGR set TLS server identity to {tigerResolvedString}")
  public void setTlsServerIdentity(String identityToken) {
    updateServerConnectionConfiguration(
        current ->
            current.withServerIdentity(new TigerConfigurationPkiIdentity(identityToken)));
  }

  /** Clears the configured TLS server identity for subsequent observations. */
  @Wenn("TGR entferne TLS-Server-Identity")
  @When("TGR clear TLS server identity")
  public void clearTlsServerIdentity() {
    updateServerConnectionConfiguration(current -> current.withServerIdentity(null));
  }

  /**
   * Configures the trust identity used to validate client certificates during subsequent TLS
   * server observations.
   *
   * @param identityToken PKI identity token in Tiger compact format
   */
  @Wenn("TGR setze TLS-Server-Trust-Identity auf {tigerResolvedString}")
  @When("TGR set TLS server trust identity to {tigerResolvedString}")
  public void setTlsServerTrustIdentity(String identityToken) {
    updateServerConnectionConfiguration(
        current ->
            current.withTrustedClientIdentity(new TigerConfigurationPkiIdentity(identityToken)));
  }

  /** Clears the configured client-certificate trust identity for subsequent TLS server observations. */
  @Wenn("TGR entferne TLS-Server-Trust-Identity")
  @When("TGR clear TLS server trust identity")
  public void clearTlsServerTrustIdentity() {
    updateServerConnectionConfiguration(current -> current.withTrustedClientIdentity(null));
  }

  /** Enables required client certificates for subsequent TLS server observations. */
  @Wenn("TGR aktiviere TLS-Server-Client-Zertifikatspflicht")
  @When("TGR require TLS server client certificates")
  public void enableTlsServerClientCertificateRequirement() {
    updateServerConnectionConfiguration(current -> current.withRequireClientCertificate(true));
  }

  /** Disables required client certificates for subsequent TLS server observations. */
  @Wenn("TGR deaktiviere TLS-Server-Client-Zertifikatspflicht")
  @When("TGR disable TLS server client certificate requirement")
  public void disableTlsServerClientCertificateRequirement() {
    updateServerConnectionConfiguration(current -> current.withRequireClientCertificate(false));
  }

  /**
   * Configures the timeout used by subsequent TLS server observations.
   *
   * @param timeoutSeconds timeout in seconds
   */
  @Wenn("TGR setze TLS-Server-Timeout auf {int} Sekunden")
  @When("TGR set TLS server timeout to {int} seconds")
  public void setTlsServerTimeoutInSeconds(int timeoutSeconds) {
    updateServerConnectionConfiguration(
        current -> current.withTimeout(Duration.ofSeconds(timeoutSeconds)));
  }

  /**
   * Configures the local bind host used by subsequent TLS server observations.
   *
   * @param bindHost local bind host
   */
  @Wenn("TGR setze TLS-Server-Bind-Host auf {tigerResolvedString}")
  @When("TGR set TLS server bind host to {tigerResolvedString}")
  public void setTlsServerBindHost(String bindHost) {
    updateServerConnectionConfiguration(current -> current.withBindHost(parseSingleToken(bindHost, "TLS server bind host")));
  }

  /**
   * Configures the server-side TLS protocol list exposed by subsequent observations.
   *
   * @param protocolTokens comma-separated protocol list
   */
  @Wenn("TGR setze TLS-Server-Protokolle auf {tigerResolvedString}")
  @When("TGR set TLS server protocols to {tigerResolvedString}")
  public void setTlsServerEnabledProtocols(String protocolTokens) {
    updateServerConnectionConfiguration(
        current -> current.withEnabledProtocols(parseTokenList(protocolTokens, "TLS server protocols")));
  }

  /** Clears any configured TLS server protocol restrictions. */
  @Wenn("TGR entferne TLS-Server-Protokollbeschränkung")
  @When("TGR clear TLS server protocol restriction")
  public void clearTlsServerEnabledProtocols() {
    updateServerConnectionConfiguration(current -> current.withEnabledProtocols(List.of()));
  }

  /**
   * Configures the server-side TLS cipher-suite list exposed by subsequent observations.
   *
   * @param cipherSuiteTokens comma-separated cipher-suite list
   */
  @Wenn("TGR setze TLS-Server-Cipher-Suites auf {tigerResolvedString}")
  @When("TGR set TLS server cipher suites to {tigerResolvedString}")
  public void setTlsServerEnabledCipherSuites(String cipherSuiteTokens) {
    updateServerConnectionConfiguration(
        current ->
            current.withEnabledCipherSuites(
                parseTokenList(cipherSuiteTokens, "TLS server cipher suites")));
  }

  /** Clears any configured TLS server cipher-suite restrictions. */
  @Wenn("TGR entferne TLS-Server-Cipher-Suite-Beschränkung")
  @When("TGR clear TLS server cipher suite restriction")
  public void clearTlsServerEnabledCipherSuites() {
    updateServerConnectionConfiguration(current -> current.withEnabledCipherSuites(List.of()));
  }

  /**
   * Configures the ALPN application protocols exposed by subsequent TLS server observations.
   *
   * @param applicationProtocolTokens comma-separated ALPN application-protocol list
   */
  @Wenn("TGR setze TLS-Server-Application-Protocols auf {tigerResolvedString}")
  @When("TGR set TLS server application protocols to {tigerResolvedString}")
  public void setTlsServerApplicationProtocols(String applicationProtocolTokens) {
    updateServerConnectionConfiguration(
        current ->
            current.withApplicationProtocols(
                parseTokenList(applicationProtocolTokens, "TLS server application protocols")));
  }

  /** Clears any configured TLS server ALPN application protocols. */
  @Wenn("TGR entferne TLS-Server-Application-Protocols")
  @When("TGR clear TLS server application protocols")
  public void clearTlsServerApplicationProtocols() {
    updateServerConnectionConfiguration(current -> current.withApplicationProtocols(List.of()));
  }

  /**
   * Starts a one-shot TLS server observation on the requested local TCP port.
   *
   * @param port requested local TCP port, or {@code 0} for an ephemeral port
   * @throws Exception if the observation server cannot be started
   */
  @Wenn("TGR starte TLS-Server-Observation auf Port {int}")
  @When("TGR start TLS server observation on port {int}")
  public void startTlsServerObservation(int port) throws Exception {
    closeLastObservationHandleQuietly();
    lastTlsServerObservationReport = null;
    lastTlsServerObservationHandle =
        tlsServerObservationRunner.start(port, tlsServerConnectionConfiguration);
  }

  /**
   * Starts a one-shot TLS server observation on an ephemeral local TCP port.
   *
   * @throws Exception if the observation server cannot be started
   */
  @Wenn("TGR starte TLS-Server-Observation auf einem zufälligen Port")
  @When("TGR start TLS server observation on an ephemeral port")
  public void startTlsServerObservationOnEphemeralPort() throws Exception {
    startTlsServerObservation(0);
  }

  /**
   * Stores the port of the running TLS server observation in a local Tiger variable.
   *
   * @param variableName local variable receiving the bound TCP port
   */
  @Wenn("TGR speichere TLS-Server-Observation-Port in lokaler Variable {tigerResolvedString}")
  @When("TGR store TLS server observation port in local variable {tigerResolvedString}")
  public void storeTlsServerObservationPort(String variableName) {
    TigerGlobalConfiguration.putValue(
        variableName,
        Integer.toString(currentServerObservationHandle().port()),
        ConfigurationValuePrecedence.LOCAL_TEST_CASE_CONTEXT);
  }

  /**
   * Waits for the last started TLS server observation to complete.
   *
   * @throws Exception if the observation fails or times out
   */
  @Wenn("TGR warte auf letzte TLS-Server-Observation")
  @When("TGR await last TLS server observation")
  public void awaitLastTlsServerObservation() throws Exception {
    lastTlsServerObservationReport = currentServerObservationHandle().awaitReport();
    closeLastObservationHandleQuietly();
  }

  /**
   * Runs a TLS test profile against one target endpoint.
   *
   * @param profileToken profile token such as {@code default} or {@code strict-modern}
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS-Testprofil {word} gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS test profile {word} against host {tigerResolvedString} on port {int}")
  public void runTlsTestProfile(String profileToken, String host, int port) {
    final TlsTestProfile profile = TlsTestProfile.fromToken(profileToken);
    lastTlsTestReport = runTlsTestProfile(profile, host, port, tlsConnectionConfiguration);
  }

  /**
   * Runs a TLS test profile and stores the serialized report in a local Tiger variable.
   *
   * @param profileToken profile token such as {@code default} or {@code strict-modern}
   * @param host target host name or IP address
   * @param port target TCP port
   * @param variableName local variable receiving the JSON report
   */
  @Wenn(
      "TGR führe TLS-Testprofil {word} gegen Host {tigerResolvedString} auf Port {int} aus und"
          + " speichere das Ergebnis in lokaler Variable {tigerResolvedString}")
  @When(
      "TGR run TLS test profile {word} against host {tigerResolvedString} on port {int} and"
          + " store the result in local variable {tigerResolvedString}")
  public void runTlsTestProfileAndStoreResult(
      String profileToken, String host, int port, String variableName) {
    runTlsTestProfile(profileToken, host, port);
    TigerGlobalConfiguration.putValue(
        variableName,
        TigerSerializationUtil.toJson(currentReport()),
        ConfigurationValuePrecedence.LOCAL_TEST_CASE_CONTEXT);
  }

  /**
   * Executes a one-off TLS handshake probe with an explicit protocol restriction.
   *
   * @param protocol TLS protocol to expose to the peer, for example {@code TLSv1.2}
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS-Protokollprobe {tigerResolvedString} gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS protocol probe {tigerResolvedString} against host {tigerResolvedString} on port {int}")
  public void runTlsProtocolProbe(String protocol, String host, int port) {
    lastTlsTestReport =
        runConnectivityProbe(
            host,
            port,
            tlsConnectionConfiguration.withEnabledProtocols(
                List.of(parseSingleToken(protocol, "TLS protocol"))));
  }

  /**
   * Executes a one-off TLS handshake probe with an explicit cipher-suite restriction.
   *
   * @param cipherSuite TLS cipher suite to expose to the peer
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS-Cipher-Suite-Probe {tigerResolvedString} gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS cipher suite probe {tigerResolvedString} against host {tigerResolvedString} on port {int}")
  public void runTlsCipherSuiteProbe(String cipherSuite, String host, int port) {
    lastTlsTestReport =
        runConnectivityProbe(
            host,
            port,
            tlsConnectionConfiguration.withEnabledCipherSuites(
                List.of(parseSingleToken(cipherSuite, "TLS cipher suite"))));
  }

  /**
   * Scans a list of TLS protocol versions against one target endpoint.
   *
   * @param protocolTokens comma-separated protocol list such as {@code TLSv1.2, TLSv1.3}
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR scanne TLS Protokolle {tigerResolvedString} gegen Host {tigerResolvedString} auf Port {int}")
  @When("TGR scan TLS protocols {tigerResolvedString} against host {tigerResolvedString} on port {int}")
  public void runTlsProtocolScan(String protocolTokens, String host, int port) {
    lastTlsProtocolScanReport =
        tlsComplianceRunner.scanProtocols(
            buildTarget(host, port),
            parseTokenList(protocolTokens, "TLS protocols"),
            tlsConnectionConfiguration);
  }

  /**
   * Scans a list of TLS cipher suites against one target endpoint.
   *
   * @param cipherSuiteTokens comma-separated cipher-suite list
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR scanne TLS Cipher Suites {tigerResolvedString} gegen Host {tigerResolvedString} auf Port {int}")
  @When("TGR scan TLS cipher suites {tigerResolvedString} against host {tigerResolvedString} on port {int}")
  public void runTlsCipherSuiteScan(String cipherSuiteTokens, String host, int port) {
    lastTlsCipherSuiteScanReport =
        tlsComplianceRunner.scanCipherSuites(
            buildTarget(host, port),
            parseTokenList(cipherSuiteTokens, "TLS cipher suites"),
            tlsConnectionConfiguration);
  }

  /**
   * Scans a list of ALPN application protocols against one target endpoint.
   *
   * @param applicationProtocolTokens comma-separated application-protocol list
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR scanne TLS Application Protocols {tigerResolvedString} gegen Host {tigerResolvedString} auf Port {int}")
  @When(
      "TGR scan TLS application protocols {tigerResolvedString} against host {tigerResolvedString} on port {int}")
  public void runTlsApplicationProtocolScan(
      String applicationProtocolTokens, String host, int port) {
    lastTlsApplicationProtocolScanReport =
        tlsComplianceRunner.scanApplicationProtocols(
            buildTarget(host, port),
            parseTokenList(applicationProtocolTokens, "TLS application protocols"),
            tlsConnectionConfiguration);
  }

  /**
   * Scans a list of TLS named groups against one target endpoint.
   *
   * @param namedGroupTokens comma-separated named-group list
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR scanne TLS Named Groups {tigerResolvedString} gegen Host {tigerResolvedString} auf Port {int}")
  @When("TGR scan TLS named groups {tigerResolvedString} against host {tigerResolvedString} on port {int}")
  public void runTlsNamedGroupScan(String namedGroupTokens, String host, int port) {
    lastTlsNamedGroupScanReport =
        tlsComplianceRunner.scanNamedGroups(
            buildTarget(host, port),
            parseTokenList(namedGroupTokens, "TLS named groups"),
            tlsConnectionConfiguration);
  }

  /**
   * Scans a list of TLS signature schemes against one target endpoint.
   *
   * @param signatureSchemeTokens comma-separated signature-scheme list
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR scanne TLS Signature Schemes {tigerResolvedString} gegen Host {tigerResolvedString} auf Port {int}")
  @When("TGR scan TLS signature schemes {tigerResolvedString} against host {tigerResolvedString} on port {int}")
  public void runTlsSignatureSchemeScan(String signatureSchemeTokens, String host, int port) {
    lastTlsSignatureSchemeScanReport =
        tlsComplianceRunner.scanSignatureSchemes(
            buildTarget(host, port),
            parseTokenList(signatureSchemeTokens, "TLS signature schemes"),
            tlsConnectionConfiguration);
  }

  /**
   * Executes the TLS 1.2 renegotiation behavior probe against one target endpoint.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS 1.2 Renegotiation-Probe gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS 1.2 renegotiation probe against host {tigerResolvedString} on port {int}")
  public void runTls12RenegotiationProbe(String host, int port) {
    lastTlsBehaviorProbeReport =
        tlsComplianceRunner.probeTls12Renegotiation(buildTarget(host, port), tlsConnectionConfiguration);
  }

  /**
   * Executes the TLS 1.2 session-resumption behavior probe against one target endpoint.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS 1.2 Session-Resumption-Probe gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS 1.2 session resumption probe against host {tigerResolvedString} on port {int}")
  public void runTls12SessionResumptionProbe(String host, int port) {
    lastTlsBehaviorProbeReport =
        tlsComplianceRunner.probeTls12SessionResumption(
            buildTarget(host, port), tlsConnectionConfiguration);
  }

  /**
   * Executes the TLS 1.2 secure-renegotiation-support probe against one target endpoint.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS 1.2 Secure-Renegotiation-Probe gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS 1.2 secure renegotiation probe against host {tigerResolvedString} on port {int}")
  public void runTls12SecureRenegotiationProbe(String host, int port) {
    lastTlsBehaviorProbeReport =
        tlsComplianceRunner.probeTls12SecureRenegotiationSupport(
            buildTarget(host, port), tlsConnectionConfiguration);
  }

  /**
   * Executes the TLS 1.2 extended-master-secret probe against one target endpoint.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS 1.2 Extended-Master-Secret-Probe gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS 1.2 extended master secret probe against host {tigerResolvedString} on port {int}")
  public void runTls12ExtendedMasterSecretProbe(String host, int port) {
    lastTlsBehaviorProbeReport =
        tlsComplianceRunner.probeTls12ExtendedMasterSecretSupport(
            buildTarget(host, port), tlsConnectionConfiguration);
  }

  /**
   * Executes the TLS 1.2 encrypt-then-mac probe against one target endpoint.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS 1.2 Encrypt-Then-Mac-Probe gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS 1.2 encrypt then mac probe against host {tigerResolvedString} on port {int}")
  public void runTls12EncryptThenMacProbe(String host, int port) {
    lastTlsBehaviorProbeReport =
        tlsComplianceRunner.probeTls12EncryptThenMacSupport(
            buildTarget(host, port), tlsConnectionConfiguration);
  }

  /**
   * Executes the TLS 1.2 fallback-SCSV rejection probe against one target endpoint.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS 1.2 Fallback-SCSV-Probe gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS 1.2 fallback SCSV probe against host {tigerResolvedString} on port {int}")
  public void runTls12FallbackScsvProbe(String host, int port) {
    lastTlsBehaviorProbeReport =
        tlsComplianceRunner.probeTls12FallbackScsvRejection(
            buildTarget(host, port), tlsConnectionConfiguration);
  }

  /**
   * Executes the OCSP stapling behavior probe against one target endpoint.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS OCSP-Stapling-Probe gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS OCSP stapling probe against host {tigerResolvedString} on port {int}")
  public void runTlsOcspStaplingProbe(String host, int port) {
    lastTlsBehaviorProbeReport =
        tlsComplianceRunner.probeOcspStapling(buildTarget(host, port), tlsConnectionConfiguration);
  }

  /**
   * Executes the unknown-extension-tolerance probe against one target endpoint.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS Unknown-Extension-Probe gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS unknown extension probe against host {tigerResolvedString} on port {int}")
  public void runTlsUnknownExtensionProbe(String host, int port) {
    lastTlsBehaviorProbeReport =
        tlsComplianceRunner.probeUnknownExtensionTolerance(
            buildTarget(host, port), tlsConnectionConfiguration);
  }

  /**
   * Executes the malformed-record behavior probe against one target endpoint.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Wenn("TGR führe TLS Malformed-Record-Probe gegen Host {tigerResolvedString} auf Port {int} aus")
  @When("TGR run TLS malformed record probe against host {tigerResolvedString} on port {int}")
  public void runTlsMalformedRecordProbe(String host, int port) {
    lastTlsBehaviorProbeReport =
        tlsComplianceRunner.probeMalformedTlsRecordRejection(
            buildTarget(host, port), tlsConnectionConfiguration);
  }

  /**
   * Stores the last TLS protocol scan report as JSON in a local Tiger variable.
   *
   * @param variableName local variable receiving the JSON report
   */
  @Wenn("TGR speichere letzten TLS-Protokollscan in lokaler Variable {tigerResolvedString}")
  @When("TGR store last TLS protocol scan in local variable {tigerResolvedString}")
  public void storeLastTlsProtocolScan(String variableName) {
    TigerGlobalConfiguration.putValue(
        variableName,
        TigerSerializationUtil.toJson(currentProtocolScanReport()),
        ConfigurationValuePrecedence.LOCAL_TEST_CASE_CONTEXT);
  }

  /**
   * Stores the last TLS cipher-suite scan report as JSON in a local Tiger variable.
   *
   * @param variableName local variable receiving the JSON report
   */
  @Wenn("TGR speichere letzten TLS-Cipher-Suite-Scan in lokaler Variable {tigerResolvedString}")
  @When("TGR store last TLS cipher suite scan in local variable {tigerResolvedString}")
  public void storeLastTlsCipherSuiteScan(String variableName) {
    TigerGlobalConfiguration.putValue(
        variableName,
        TigerSerializationUtil.toJson(currentCipherSuiteScanReport()),
        ConfigurationValuePrecedence.LOCAL_TEST_CASE_CONTEXT);
  }

  /**
   * Stores the last TLS application-protocol scan report as JSON in a local Tiger variable.
   *
   * @param variableName local variable receiving the JSON report
   */
  @Wenn("TGR speichere letzten TLS-Application-Protocol-Scan in lokaler Variable {tigerResolvedString}")
  @When("TGR store last TLS application protocol scan in local variable {tigerResolvedString}")
  public void storeLastTlsApplicationProtocolScan(String variableName) {
    TigerGlobalConfiguration.putValue(
        variableName,
        TigerSerializationUtil.toJson(currentApplicationProtocolScanReport()),
        ConfigurationValuePrecedence.LOCAL_TEST_CASE_CONTEXT);
  }

  /**
   * Stores the last TLS named-group scan report as JSON in a local Tiger variable.
   *
   * @param variableName local variable receiving the JSON report
   */
  @Wenn("TGR speichere letzten TLS-Named-Group-Scan in lokaler Variable {tigerResolvedString}")
  @When("TGR store last TLS named group scan in local variable {tigerResolvedString}")
  public void storeLastTlsNamedGroupScan(String variableName) {
    TigerGlobalConfiguration.putValue(
        variableName,
        TigerSerializationUtil.toJson(currentNamedGroupScanReport()),
        ConfigurationValuePrecedence.LOCAL_TEST_CASE_CONTEXT);
  }

  /**
   * Stores the last TLS signature-scheme scan report as JSON in a local Tiger variable.
   *
   * @param variableName local variable receiving the JSON report
   */
  @Wenn("TGR speichere letzten TLS-Signature-Scheme-Scan in lokaler Variable {tigerResolvedString}")
  @When("TGR store last TLS signature scheme scan in local variable {tigerResolvedString}")
  public void storeLastTlsSignatureSchemeScan(String variableName) {
    TigerGlobalConfiguration.putValue(
        variableName,
        TigerSerializationUtil.toJson(currentSignatureSchemeScanReport()),
        ConfigurationValuePrecedence.LOCAL_TEST_CASE_CONTEXT);
  }

  /**
   * Stores the last TLS behavior probe report as JSON in a local Tiger variable.
   *
   * @param variableName local variable receiving the JSON report
   */
  @Wenn("TGR speichere letzte TLS-Behavior-Probe in lokaler Variable {tigerResolvedString}")
  @When("TGR store last TLS behavior probe in local variable {tigerResolvedString}")
  public void storeLastTlsBehaviorProbe(String variableName) {
    TigerGlobalConfiguration.putValue(
        variableName,
        TigerSerializationUtil.toJson(currentBehaviorProbeReport()),
        ConfigurationValuePrecedence.LOCAL_TEST_CASE_CONTEXT);
  }

  /**
   * Stores the last TLS server observation report as JSON in a local Tiger variable.
   *
   * @param variableName local variable receiving the JSON report
   */
  @Wenn("TGR speichere letzte TLS-Server-Observation in lokaler Variable {tigerResolvedString}")
  @When("TGR store last TLS server observation in local variable {tigerResolvedString}")
  public void storeLastTlsServerObservation(String variableName) {
    TigerGlobalConfiguration.putValue(
        variableName,
        TigerSerializationUtil.toJson(currentServerObservationReport()),
        ConfigurationValuePrecedence.LOCAL_TEST_CASE_CONTEXT);
  }

  /**
   * Asserts the overall verdict of the last executed TLS profile.
   *
   * @param verdictToken expected verdict token
   */
  @Dann("TGR prüfe TLS-Gesamturteil ist {word}")
  @Then("TGR assert TLS overall verdict is {word}")
  public void assertOverallTlsVerdict(String verdictToken) {
    assertThat(currentReport().overallVerdict()).isEqualTo(parseVerdict(verdictToken));
  }

  /**
   * Asserts one contained TLS check verdict.
   *
   * @param testCaseToken test case token such as {@code handshake}
   * @param verdictToken expected verdict token
   */
  @Dann("TGR prüfe TLS-Test {word} ist {word}")
  @Then("TGR assert TLS test {word} is {word}")
  public void assertTlsTestVerdict(String testCaseToken, String verdictToken) {
    assertThat(currentReport().findResult(TlsTestCase.fromToken(testCaseToken)))
        .hasValueSatisfying(
            result -> assertThat(result.verdict()).isEqualTo(parseVerdict(verdictToken)));
  }

  /**
   * Asserts that the details of one contained TLS check match the provided regular expression.
   *
   * @param testCaseToken test case token such as {@code handshake}
   * @param regex expected regular expression
   */
  @Dann("TGR prüfe TLS-Test {word} Detail stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert TLS test {word} detail matches {tigerResolvedString}")
  public void assertTlsTestDetailMatches(String testCaseToken, String regex) {
    assertThat(currentReport().findResult(TlsTestCase.fromToken(testCaseToken)))
        .hasValueSatisfying(result -> assertThat(result.details()).matches(regex));
  }

  /**
   * Asserts the primary reproduction command of one contained TLS profile check.
   *
   * @param testCaseToken test case token such as {@code handshake}
   * @param regex expected regular expression for the primary reproduction command
   */
  @Dann("TGR prüfe TLS-Test {word} OpenSSL-Kommando stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert TLS test {word} OpenSSL command matches {tigerResolvedString}")
  public void assertTlsTestOpenSslCommandMatches(String testCaseToken, String regex) {
    assertThat(currentProfileResult(testCaseToken).evidence().primaryReproductionCommand())
        .hasValueSatisfying(command -> assertThat(command).matches(regex));
  }

  /**
   * Asserts the negotiated protocol reported by one TLS check.
   *
   * @param testCaseToken test case token such as {@code handshake}
   * @param protocol expected negotiated protocol
   */
  @Dann("TGR prüfe TLS-Test {word} verhandelt Protokoll {tigerResolvedString}")
  @Then("TGR assert TLS test {word} negotiated protocol {tigerResolvedString}")
  public void assertTlsTestNegotiatedProtocol(String testCaseToken, String protocol) {
    assertThat(currentReport().findResult(TlsTestCase.fromToken(testCaseToken)))
        .hasValueSatisfying(
            result ->
                assertThat(extractSessionSummary(result).negotiatedProtocol()).isEqualTo(protocol));
  }

  /**
   * Asserts the negotiated cipher suite reported by one TLS check.
   *
   * @param testCaseToken test case token such as {@code handshake}
   * @param cipherSuite expected negotiated cipher suite
   */
  @Dann("TGR prüfe TLS-Test {word} verhandelt Cipher Suite {tigerResolvedString}")
  @Then("TGR assert TLS test {word} negotiated cipher suite {tigerResolvedString}")
  public void assertTlsTestNegotiatedCipherSuite(String testCaseToken, String cipherSuite) {
    assertThat(currentReport().findResult(TlsTestCase.fromToken(testCaseToken)))
        .hasValueSatisfying(
            result ->
                assertThat(extractSessionSummary(result).negotiatedCipherSuite())
                    .isEqualTo(cipherSuite));
  }

  /**
   * Executes a one-off probe and asserts that the peer accepts the specified TLS protocol.
   *
   * @param protocol expected protocol accepted by the peer
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} akzeptiert TLS Protokoll {tigerResolvedString}")
  @Then("TGR assert host {tigerResolvedString} on port {int} accepts TLS protocol {tigerResolvedString}")
  public void assertTlsProtocolAccepted(String host, int port, String protocol) {
    runTlsProtocolProbe(protocol, host, port);
    assertTlsTestVerdict(TlsTestCase.HANDSHAKE.token(), TlsTestVerdict.PASSED.name());
    assertTlsTestNegotiatedProtocol(TlsTestCase.HANDSHAKE.token(), protocol);
  }

  /**
   * Executes a one-off probe and asserts that the peer rejects the specified TLS protocol.
   *
   * @param protocol expected protocol rejected by the peer
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} lehnt TLS Protokoll {tigerResolvedString} ab")
  @Then("TGR assert host {tigerResolvedString} on port {int} rejects TLS protocol {tigerResolvedString}")
  public void assertTlsProtocolRejected(String host, int port, String protocol) {
    runTlsProtocolProbe(protocol, host, port);
    assertTlsTestVerdict(TlsTestCase.HANDSHAKE.token(), TlsTestVerdict.FAILED.name());
  }

  /**
   * Executes a one-off probe and asserts that the peer accepts the specified TLS cipher suite.
   *
   * @param cipherSuite expected cipher suite accepted by the peer
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} akzeptiert TLS Cipher Suite {tigerResolvedString}")
  @Then("TGR assert host {tigerResolvedString} on port {int} accepts TLS cipher suite {tigerResolvedString}")
  public void assertTlsCipherSuiteAccepted(String host, int port, String cipherSuite) {
    runTlsCipherSuiteProbe(cipherSuite, host, port);
    assertTlsTestVerdict(TlsTestCase.HANDSHAKE.token(), TlsTestVerdict.PASSED.name());
    assertTlsTestNegotiatedCipherSuite(TlsTestCase.HANDSHAKE.token(), cipherSuite);
  }

  /**
   * Executes a one-off probe and asserts that the peer rejects the specified TLS cipher suite.
   *
   * @param cipherSuite expected cipher suite rejected by the peer
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} lehnt TLS Cipher Suite {tigerResolvedString} ab")
  @Then("TGR assert host {tigerResolvedString} on port {int} rejects TLS cipher suite {tigerResolvedString}")
  public void assertTlsCipherSuiteRejected(String host, int port, String cipherSuite) {
    runTlsCipherSuiteProbe(cipherSuite, host, port);
    assertTlsTestVerdict(TlsTestCase.HANDSHAKE.token(), TlsTestVerdict.FAILED.name());
  }

  /**
   * Executes an application-protocol scan and asserts that the peer accepts the specified ALPN
   * application protocol.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   * @param applicationProtocol expected ALPN application protocol accepted by the peer
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} akzeptiert TLS Application Protocol {tigerResolvedString}")
  @Then(
      "TGR assert host {tigerResolvedString} on port {int} accepts TLS application protocol {tigerResolvedString}")
  public void assertTlsApplicationProtocolAccepted(
      String host, int port, String applicationProtocol) {
    runTlsApplicationProtocolScan(applicationProtocol, host, port);
    assertLastTlsApplicationProtocolScanAccepts(applicationProtocol);
  }

  /**
   * Executes an application-protocol scan and asserts that the peer rejects the specified ALPN
   * application protocol.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   * @param applicationProtocol expected ALPN application protocol rejected by the peer
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} lehnt TLS Application Protocol {tigerResolvedString} ab")
  @Then(
      "TGR assert host {tigerResolvedString} on port {int} rejects TLS application protocol {tigerResolvedString}")
  public void assertTlsApplicationProtocolRejected(
      String host, int port, String applicationProtocol) {
    runTlsApplicationProtocolScan(applicationProtocol, host, port);
    assertLastTlsApplicationProtocolScanRejects(applicationProtocol);
  }

  /**
   * Executes a named-group scan and asserts that the peer accepts the specified named group.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   * @param namedGroup expected named group accepted by the peer
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} akzeptiert TLS Named Group {tigerResolvedString}")
  @Then("TGR assert host {tigerResolvedString} on port {int} accepts TLS named group {tigerResolvedString}")
  public void assertTlsNamedGroupAccepted(String host, int port, String namedGroup) {
    runTlsNamedGroupScan(namedGroup, host, port);
    assertLastTlsNamedGroupScanAccepts(namedGroup);
  }

  /**
   * Executes a named-group scan and asserts that the peer rejects the specified named group.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   * @param namedGroup expected named group rejected by the peer
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} lehnt TLS Named Group {tigerResolvedString} ab")
  @Then("TGR assert host {tigerResolvedString} on port {int} rejects TLS named group {tigerResolvedString}")
  public void assertTlsNamedGroupRejected(String host, int port, String namedGroup) {
    runTlsNamedGroupScan(namedGroup, host, port);
    assertLastTlsNamedGroupScanRejects(namedGroup);
  }

  /**
   * Executes a signature-scheme scan and asserts that the peer accepts the specified signature
   * scheme.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   * @param signatureScheme expected signature scheme accepted by the peer
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} akzeptiert TLS Signature Scheme {tigerResolvedString}")
  @Then("TGR assert host {tigerResolvedString} on port {int} accepts TLS signature scheme {tigerResolvedString}")
  public void assertTlsSignatureSchemeAccepted(String host, int port, String signatureScheme) {
    runTlsSignatureSchemeScan(signatureScheme, host, port);
    assertLastTlsSignatureSchemeScanAccepts(signatureScheme);
  }

  /**
   * Executes a signature-scheme scan and asserts that the peer rejects the specified signature
   * scheme.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   * @param signatureScheme expected signature scheme rejected by the peer
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} lehnt TLS Signature Scheme {tigerResolvedString} ab")
  @Then("TGR assert host {tigerResolvedString} on port {int} rejects TLS signature scheme {tigerResolvedString}")
  public void assertTlsSignatureSchemeRejected(String host, int port, String signatureScheme) {
    runTlsSignatureSchemeScan(signatureScheme, host, port);
    assertLastTlsSignatureSchemeScanRejects(signatureScheme);
  }

  /**
   * Asserts that the last protocol scan accepted one specific protocol version.
   *
   * @param protocol expected accepted protocol version
   */
  @Dann("TGR prüfe letzter TLS-Protokollscan akzeptiert {tigerResolvedString}")
  @Then("TGR assert last TLS protocol scan accepts {tigerResolvedString}")
  public void assertLastTlsProtocolScanAccepts(String protocol) {
    assertThat(currentProtocolScanReport().findResult(parseSingleToken(protocol, "TLS protocol")))
        .hasValueSatisfying(
            result -> assertThat(result.verdict()).isEqualTo(TlsTestVerdict.PASSED));
  }

  /**
   * Asserts that the last protocol scan rejected one specific protocol version.
   *
   * @param protocol expected rejected protocol version
   */
  @Dann("TGR prüfe letzter TLS-Protokollscan lehnt {tigerResolvedString} ab")
  @Then("TGR assert last TLS protocol scan rejects {tigerResolvedString}")
  public void assertLastTlsProtocolScanRejects(String protocol) {
    assertThat(currentProtocolScanReport().findResult(parseSingleToken(protocol, "TLS protocol")))
        .hasValueSatisfying(
            result -> assertThat(result.verdict()).isEqualTo(TlsTestVerdict.FAILED));
  }

  /**
   * Asserts the full accepted protocol list of the last protocol scan.
   *
   * @param protocolTokens expected comma-separated accepted protocol list
   */
  @Dann("TGR prüfe letzter TLS-Protokollscan akzeptierte Protokolle sind {tigerResolvedString}")
  @Then("TGR assert last TLS protocol scan accepted protocols equal {tigerResolvedString}")
  public void assertLastTlsProtocolScanAcceptedProtocols(String protocolTokens) {
    assertThat(currentProtocolScanReport().supportedFeatures())
        .containsExactlyElementsOf(parseTokenList(protocolTokens, "TLS protocols"));
  }

  /**
   * Asserts that the last cipher-suite scan accepted one specific cipher suite.
   *
   * @param cipherSuite expected accepted cipher suite
   */
  @Dann("TGR prüfe letzter TLS-Cipher-Suite-Scan akzeptiert {tigerResolvedString}")
  @Then("TGR assert last TLS cipher suite scan accepts {tigerResolvedString}")
  public void assertLastTlsCipherSuiteScanAccepts(String cipherSuite) {
    assertThat(
            currentCipherSuiteScanReport()
                .findResult(parseSingleToken(cipherSuite, "TLS cipher suite")))
        .hasValueSatisfying(
            result -> assertThat(result.verdict()).isEqualTo(TlsTestVerdict.PASSED));
  }

  /**
   * Asserts that the last cipher-suite scan rejected one specific cipher suite.
   *
   * @param cipherSuite expected rejected cipher suite
   */
  @Dann("TGR prüfe letzter TLS-Cipher-Suite-Scan lehnt {tigerResolvedString} ab")
  @Then("TGR assert last TLS cipher suite scan rejects {tigerResolvedString}")
  public void assertLastTlsCipherSuiteScanRejects(String cipherSuite) {
    assertThat(
            currentCipherSuiteScanReport()
                .findResult(parseSingleToken(cipherSuite, "TLS cipher suite")))
        .hasValueSatisfying(
            result -> assertThat(result.verdict()).isEqualTo(TlsTestVerdict.FAILED));
  }

  /**
   * Asserts the full accepted cipher-suite list of the last cipher-suite scan.
   *
   * @param cipherSuiteTokens expected comma-separated accepted cipher-suite list
   */
  @Dann("TGR prüfe letzter TLS-Cipher-Suite-Scan akzeptierte Cipher Suites sind {tigerResolvedString}")
  @Then("TGR assert last TLS cipher suite scan accepted cipher suites equal {tigerResolvedString}")
  public void assertLastTlsCipherSuiteScanAcceptedCipherSuites(String cipherSuiteTokens) {
    assertThat(currentCipherSuiteScanReport().supportedFeatures())
        .containsExactlyElementsOf(parseTokenList(cipherSuiteTokens, "TLS cipher suites"));
  }

  /**
   * Asserts that the last application-protocol scan accepted one specific ALPN application
   * protocol.
   *
   * @param applicationProtocol expected accepted ALPN application protocol
   */
  @Dann("TGR prüfe letzter TLS-Application-Protocol-Scan akzeptiert {tigerResolvedString}")
  @Then("TGR assert last TLS application protocol scan accepts {tigerResolvedString}")
  public void assertLastTlsApplicationProtocolScanAccepts(String applicationProtocol) {
    assertThat(currentApplicationProtocolScanResult(applicationProtocol))
        .extracting(TlsFeatureSupportResult::verdict)
        .isEqualTo(TlsTestVerdict.PASSED);
  }

  /**
   * Asserts that the last application-protocol scan rejected one specific ALPN application
   * protocol.
   *
   * @param applicationProtocol expected rejected ALPN application protocol
   */
  @Dann("TGR prüfe letzter TLS-Application-Protocol-Scan lehnt {tigerResolvedString} ab")
  @Then("TGR assert last TLS application protocol scan rejects {tigerResolvedString}")
  public void assertLastTlsApplicationProtocolScanRejects(String applicationProtocol) {
    assertThat(currentApplicationProtocolScanResult(applicationProtocol))
        .extracting(TlsFeatureSupportResult::verdict)
        .isEqualTo(TlsTestVerdict.FAILED);
  }

  /**
   * Asserts the full accepted application-protocol list of the last application-protocol scan.
   *
   * @param applicationProtocolTokens expected comma-separated accepted application-protocol list
   */
  @Dann("TGR prüfe letzter TLS-Application-Protocol-Scan akzeptierte Application Protocols sind {tigerResolvedString}")
  @Then(
      "TGR assert last TLS application protocol scan accepted application protocols equal {tigerResolvedString}")
  public void assertLastTlsApplicationProtocolScanAcceptedProtocols(
      String applicationProtocolTokens) {
    assertThat(currentApplicationProtocolScanReport().supportedFeatures())
        .containsExactlyElementsOf(
            parseTokenList(applicationProtocolTokens, "TLS application protocols"));
  }

  /**
   * Asserts that the last named-group scan accepted one specific named group.
   *
   * @param namedGroup expected accepted named group
   */
  @Dann("TGR prüfe letzter TLS-Named-Group-Scan akzeptiert {tigerResolvedString}")
  @Then("TGR assert last TLS named group scan accepts {tigerResolvedString}")
  public void assertLastTlsNamedGroupScanAccepts(String namedGroup) {
    assertThat(currentNamedGroupScanResult(namedGroup))
        .extracting(TlsFeatureSupportResult::verdict)
        .isEqualTo(TlsTestVerdict.PASSED);
  }

  /**
   * Asserts that the last named-group scan rejected one specific named group.
   *
   * @param namedGroup expected rejected named group
   */
  @Dann("TGR prüfe letzter TLS-Named-Group-Scan lehnt {tigerResolvedString} ab")
  @Then("TGR assert last TLS named group scan rejects {tigerResolvedString}")
  public void assertLastTlsNamedGroupScanRejects(String namedGroup) {
    assertThat(currentNamedGroupScanResult(namedGroup))
        .extracting(TlsFeatureSupportResult::verdict)
        .isEqualTo(TlsTestVerdict.FAILED);
  }

  /**
   * Asserts that the last signature-scheme scan accepted one specific signature scheme.
   *
   * @param signatureScheme expected accepted signature scheme
   */
  @Dann("TGR prüfe letzter TLS-Signature-Scheme-Scan akzeptiert {tigerResolvedString}")
  @Then("TGR assert last TLS signature scheme scan accepts {tigerResolvedString}")
  public void assertLastTlsSignatureSchemeScanAccepts(String signatureScheme) {
    assertThat(currentSignatureSchemeScanResult(signatureScheme))
        .extracting(TlsFeatureSupportResult::verdict)
        .isEqualTo(TlsTestVerdict.PASSED);
  }

  /**
   * Asserts that the last signature-scheme scan rejected one specific signature scheme.
   *
   * @param signatureScheme expected rejected signature scheme
   */
  @Dann("TGR prüfe letzter TLS-Signature-Scheme-Scan lehnt {tigerResolvedString} ab")
  @Then("TGR assert last TLS signature scheme scan rejects {tigerResolvedString}")
  public void assertLastTlsSignatureSchemeScanRejects(String signatureScheme) {
    assertThat(currentSignatureSchemeScanResult(signatureScheme))
        .extracting(TlsFeatureSupportResult::verdict)
        .isEqualTo(TlsTestVerdict.FAILED);
  }

  /**
   * Asserts the verdict of the last TLS behavior probe.
   *
   * @param verdictToken expected verdict token
   */
  @Dann("TGR prüfe letzte TLS-Behavior-Probe ist {word}")
  @Then("TGR assert last TLS behavior probe is {word}")
  public void assertLastTlsBehaviorProbeVerdict(String verdictToken) {
    assertThat(currentBehaviorProbeReport().verdict()).isEqualTo(parseVerdict(verdictToken));
  }

  /**
   * Asserts that the details of the last TLS behavior probe match a regular expression.
   *
   * @param regex expected regular expression
   */
  @Dann("TGR prüfe letzte TLS-Behavior-Probe Detail stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert last TLS behavior probe detail matches {tigerResolvedString}")
  public void assertLastTlsBehaviorProbeDetailMatches(String regex) {
    assertThat(currentBehaviorProbeReport().details()).matches(regex);
  }

  /**
   * Asserts the primary reproduction command of the last TLS behavior probe.
   *
   * @param regex expected regular expression for the primary reproduction command
   */
  @Dann("TGR prüfe letztes TLS-Behavior-Probe-OpenSSL-Kommando stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert last TLS behavior probe OpenSSL command matches {tigerResolvedString}")
  public void assertLastTlsBehaviorProbeOpenSslCommandMatches(String regex) {
    assertThat(currentBehaviorProbeReport().evidence().primaryReproductionCommand())
        .hasValueSatisfying(command -> assertThat(command).matches(regex));
  }

  /**
   * Asserts the verdict of the last TLS server observation.
   *
   * @param verdictToken expected verdict token
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation ist {word}")
  @Then("TGR assert last TLS server observation is {word}")
  public void assertLastTlsServerObservationVerdict(String verdictToken) {
    assertThat(currentServerObservationReport().verdict()).isEqualTo(parseVerdict(verdictToken));
  }

  /**
   * Asserts that the details of the last TLS server observation match a regular expression.
   *
   * @param regex expected regular expression
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation Detail stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert last TLS server observation detail matches {tigerResolvedString}")
  public void assertLastTlsServerObservationDetailMatches(String regex) {
    assertThat(currentServerObservationReport().details()).matches(regex);
  }

  /**
   * Asserts the negotiated protocol reported by the last TLS server observation.
   *
   * @param protocol expected negotiated protocol
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation verhandelt Protokoll {tigerResolvedString}")
  @Then("TGR assert last TLS server observation negotiated protocol {tigerResolvedString}")
  public void assertLastTlsServerObservationNegotiatedProtocol(String protocol) {
    assertThat(currentServerObservationSessionSummary().negotiatedProtocol()).isEqualTo(protocol);
  }

  /**
   * Asserts the negotiated cipher suite reported by the last TLS server observation.
   *
   * @param cipherSuite expected negotiated cipher suite
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation verhandelt Cipher Suite {tigerResolvedString}")
  @Then("TGR assert last TLS server observation negotiated cipher suite {tigerResolvedString}")
  public void assertLastTlsServerObservationNegotiatedCipherSuite(String cipherSuite) {
    assertThat(currentServerObservationSessionSummary().negotiatedCipherSuite())
        .isEqualTo(cipherSuite);
  }

  /**
   * Asserts the negotiated ALPN application protocol reported by the last TLS server observation.
   *
   * @param applicationProtocol expected negotiated ALPN application protocol
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation verhandelt Application Protocol {tigerResolvedString}")
  @Then(
      "TGR assert last TLS server observation negotiated application protocol {tigerResolvedString}")
  public void assertLastTlsServerObservationApplicationProtocol(String applicationProtocol) {
    assertThat(currentServerObservationReport().negotiatedApplicationProtocol())
        .isEqualTo(parseSingleToken(applicationProtocol, "TLS application protocol"));
  }

  /**
   * Asserts that the last TLS server observation captured one requested SNI server name.
   *
   * @param serverName expected requested SNI server name
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation enthält SNI {tigerResolvedString}")
  @Then("TGR assert last TLS server observation contains SNI {tigerResolvedString}")
  public void assertLastTlsServerObservationContainsSni(String serverName) {
    assertThat(currentServerObservationReport().requestedServerNames())
        .contains(parseSingleToken(serverName, "TLS SNI server name"));
  }

  /**
   * Asserts that the last TLS server observation captured no requested SNI server names.
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation enthält kein SNI")
  @Then("TGR assert last TLS server observation contains no SNI")
  public void assertLastTlsServerObservationContainsNoSni() {
    assertThat(currentServerObservationReport().requestedServerNames()).isEmpty();
  }

  /**
   * Asserts that the last TLS server observation captured at least one client certificate.
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation enthält Client-Zertifikat")
  @Then("TGR assert last TLS server observation contains client certificate")
  public void assertLastTlsServerObservationContainsClientCertificate() {
    assertThat(currentServerObservationReport().clientCertificateSubjects()).isNotEmpty();
  }

  /**
   * Asserts that the last TLS server observation captured no client certificate.
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation enthält kein Client-Zertifikat")
  @Then("TGR assert last TLS server observation contains no client certificate")
  public void assertLastTlsServerObservationContainsNoClientCertificate() {
    assertThat(currentServerObservationReport().clientCertificateSubjects()).isEmpty();
  }

  /**
   * Asserts that one client-certificate subject captured by the last TLS server observation
   * matches a regular expression.
   *
   * @param regex expected regular expression for one captured client-certificate subject
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation Client-Zertifikat-Betreff stimmt überein mit {tigerResolvedString}")
  @Then(
      "TGR assert last TLS server observation client certificate subject matches {tigerResolvedString}")
  public void assertLastTlsServerObservationClientCertificateSubjectMatches(String regex) {
    assertThat(currentServerObservationReport().clientCertificateSubjects())
        .anySatisfy(subject -> assertThat(subject).matches(regex));
  }

  /**
   * Asserts that the remote address captured by the last TLS server observation matches a regular
   * expression.
   *
   * @param regex expected regular expression for the remote client address
   */
  @Dann("TGR prüfe letzte TLS-Server-Observation Remote-Adresse stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert last TLS server observation remote address matches {tigerResolvedString}")
  public void assertLastTlsServerObservationRemoteAddressMatches(String regex) {
    assertThat(currentServerObservationReport().remoteAddress()).matches(regex);
  }

  /**
   * Asserts the primary OpenSSL reproduction command of the last TLS server observation.
   *
   * @param regex expected regular expression for the primary reproduction command
   */
  @Dann("TGR prüfe letztes TLS-Server-Observation-OpenSSL-Kommando stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert last TLS server observation OpenSSL command matches {tigerResolvedString}")
  public void assertLastTlsServerObservationOpenSslCommandMatches(String regex) {
    assertThat(currentServerObservationReport().evidence().primaryReproductionCommand())
        .hasValueSatisfying(command -> assertThat(command).matches(regex));
  }

  /**
   * Asserts the primary reproduction command for one protocol scan result.
   *
   * @param protocol scanned protocol token
   * @param regex expected regular expression for the primary reproduction command
   */
  @Dann("TGR prüfe TLS-Protokollscan für {tigerResolvedString} OpenSSL-Kommando stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert TLS protocol scan for {tigerResolvedString} OpenSSL command matches {tigerResolvedString}")
  public void assertTlsProtocolScanOpenSslCommandMatches(String protocol, String regex) {
    assertThat(currentProtocolScanResult(protocol).evidence().primaryReproductionCommand())
        .hasValueSatisfying(command -> assertThat(command).matches(regex));
  }

  /**
   * Asserts the primary reproduction command for one cipher-suite scan result.
   *
   * @param cipherSuite scanned cipher-suite token
   * @param regex expected regular expression for the primary reproduction command
   */
  @Dann("TGR prüfe TLS-Cipher-Suite-Scan für {tigerResolvedString} OpenSSL-Kommando stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert TLS cipher suite scan for {tigerResolvedString} OpenSSL command matches {tigerResolvedString}")
  public void assertTlsCipherSuiteScanOpenSslCommandMatches(String cipherSuite, String regex) {
    assertThat(currentCipherSuiteScanResult(cipherSuite).evidence().primaryReproductionCommand())
        .hasValueSatisfying(command -> assertThat(command).matches(regex));
  }

  /**
   * Asserts the primary reproduction command for one application-protocol scan result.
   *
   * @param applicationProtocol scanned ALPN application-protocol token
   * @param regex expected regular expression for the primary reproduction command
   */
  @Dann("TGR prüfe TLS-Application-Protocol-Scan für {tigerResolvedString} OpenSSL-Kommando stimmt überein mit {tigerResolvedString}")
  @Then(
      "TGR assert TLS application protocol scan for {tigerResolvedString} OpenSSL command matches {tigerResolvedString}")
  public void assertTlsApplicationProtocolScanOpenSslCommandMatches(
      String applicationProtocol, String regex) {
    assertThat(
            currentApplicationProtocolScanResult(applicationProtocol)
                .evidence()
                .primaryReproductionCommand())
        .hasValueSatisfying(command -> assertThat(command).matches(regex));
  }

  /**
   * Asserts the primary reproduction command for one named-group scan result.
   *
   * @param namedGroup scanned named-group token
   * @param regex expected regular expression for the primary reproduction command
   */
  @Dann("TGR prüfe TLS-Named-Group-Scan für {tigerResolvedString} OpenSSL-Kommando stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert TLS named group scan for {tigerResolvedString} OpenSSL command matches {tigerResolvedString}")
  public void assertTlsNamedGroupScanOpenSslCommandMatches(String namedGroup, String regex) {
    assertThat(currentNamedGroupScanResult(namedGroup).evidence().primaryReproductionCommand())
        .hasValueSatisfying(command -> assertThat(command).matches(regex));
  }

  /**
   * Asserts the primary reproduction command for one signature-scheme scan result.
   *
   * @param signatureScheme scanned signature-scheme token
   * @param regex expected regular expression for the primary reproduction command
   */
  @Dann("TGR prüfe TLS-Signature-Scheme-Scan für {tigerResolvedString} OpenSSL-Kommando stimmt überein mit {tigerResolvedString}")
  @Then("TGR assert TLS signature scheme scan for {tigerResolvedString} OpenSSL command matches {tigerResolvedString}")
  public void assertTlsSignatureSchemeScanOpenSslCommandMatches(
      String signatureScheme, String regex) {
    assertThat(
            currentSignatureSchemeScanResult(signatureScheme)
                .evidence()
                .primaryReproductionCommand())
        .hasValueSatisfying(command -> assertThat(command).matches(regex));
  }

  /**
   * Executes a renegotiation probe and asserts that TLS 1.2 renegotiation succeeds.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} unterstützt TLS 1.2 Renegotiation")
  @Then("TGR assert host {tigerResolvedString} on port {int} supports TLS 1.2 renegotiation")
  public void assertTls12RenegotiationSupported(String host, int port) {
    runTls12RenegotiationProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.PASSED.name());
  }

  /**
   * Executes a renegotiation probe and asserts that TLS 1.2 renegotiation is rejected.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} lehnt TLS 1.2 Renegotiation ab")
  @Then("TGR assert host {tigerResolvedString} on port {int} rejects TLS 1.2 renegotiation")
  public void assertTls12RenegotiationRejected(String host, int port) {
    runTls12RenegotiationProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.FAILED.name());
  }

  /**
   * Executes a session-resumption probe and asserts that TLS 1.2 session resumption succeeds.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} unterstützt TLS 1.2 Session Resumption")
  @Then("TGR assert host {tigerResolvedString} on port {int} supports TLS 1.2 session resumption")
  public void assertTls12SessionResumptionSupported(String host, int port) {
    runTls12SessionResumptionProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.PASSED.name());
  }

  /**
   * Executes a session-resumption probe and asserts that TLS 1.2 session resumption is rejected.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} lehnt TLS 1.2 Session Resumption ab")
  @Then("TGR assert host {tigerResolvedString} on port {int} rejects TLS 1.2 session resumption")
  public void assertTls12SessionResumptionRejected(String host, int port) {
    runTls12SessionResumptionProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.FAILED.name());
  }

  /**
   * Executes the secure-renegotiation probe and asserts that the target advertises secure
   * renegotiation support.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} unterstützt TLS 1.2 Secure Renegotiation")
  @Then("TGR assert host {tigerResolvedString} on port {int} supports TLS 1.2 secure renegotiation")
  public void assertTls12SecureRenegotiationSupported(String host, int port) {
    runTls12SecureRenegotiationProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.PASSED.name());
  }

  /**
   * Executes the secure-renegotiation probe and asserts that the target does not advertise secure
   * renegotiation support.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} unterstützt kein TLS 1.2 Secure Renegotiation")
  @Then("TGR assert host {tigerResolvedString} on port {int} does not support TLS 1.2 secure renegotiation")
  public void assertTls12SecureRenegotiationRejected(String host, int port) {
    runTls12SecureRenegotiationProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.FAILED.name());
  }

  /**
   * Executes the extended-master-secret probe and asserts that the target negotiates the extension.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} unterstützt TLS 1.2 Extended Master Secret")
  @Then("TGR assert host {tigerResolvedString} on port {int} supports TLS 1.2 extended master secret")
  public void assertTls12ExtendedMasterSecretSupported(String host, int port) {
    runTls12ExtendedMasterSecretProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.PASSED.name());
  }

  /**
   * Executes the extended-master-secret probe and asserts that the target does not negotiate the
   * extension.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} unterstützt kein TLS 1.2 Extended Master Secret")
  @Then("TGR assert host {tigerResolvedString} on port {int} does not support TLS 1.2 extended master secret")
  public void assertTls12ExtendedMasterSecretRejected(String host, int port) {
    runTls12ExtendedMasterSecretProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.FAILED.name());
  }

  /**
   * Executes the encrypt-then-mac probe and asserts that the target negotiates the extension.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} unterstützt TLS 1.2 Encrypt Then Mac")
  @Then("TGR assert host {tigerResolvedString} on port {int} supports TLS 1.2 encrypt then mac")
  public void assertTls12EncryptThenMacSupported(String host, int port) {
    runTls12EncryptThenMacProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.PASSED.name());
  }

  /**
   * Executes the encrypt-then-mac probe and asserts that the target does not negotiate the
   * extension.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} unterstützt kein TLS 1.2 Encrypt Then Mac")
  @Then(
      "TGR assert host {tigerResolvedString} on port {int} does not support TLS 1.2 encrypt then mac")
  public void assertTls12EncryptThenMacRejected(String host, int port) {
    runTls12EncryptThenMacProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.FAILED.name());
  }

  /**
   * Executes the fallback-SCSV probe and asserts that the target rejects the fallback handshake.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} lehnt TLS 1.2 Fallback SCSV ab")
  @Then("TGR assert host {tigerResolvedString} on port {int} rejects TLS 1.2 fallback SCSV")
  public void assertTls12FallbackScsvRejected(String host, int port) {
    runTls12FallbackScsvProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.PASSED.name());
  }

  /**
   * Executes the fallback-SCSV probe and asserts that the target does not reject the fallback
   * handshake.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} akzeptiert TLS 1.2 Fallback SCSV")
  @Then("TGR assert host {tigerResolvedString} on port {int} accepts TLS 1.2 fallback SCSV")
  public void assertTls12FallbackScsvAccepted(String host, int port) {
    runTls12FallbackScsvProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.FAILED.name());
  }

  /**
   * Executes the OCSP stapling probe and asserts that the target provides a staple.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} unterstützt TLS OCSP Stapling")
  @Then("TGR assert host {tigerResolvedString} on port {int} supports TLS OCSP stapling")
  public void assertTlsOcspStaplingSupported(String host, int port) {
    runTlsOcspStaplingProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.PASSED.name());
  }

  /**
   * Executes the OCSP stapling probe and asserts that the target does not provide a staple.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} unterstützt kein TLS OCSP Stapling")
  @Then("TGR assert host {tigerResolvedString} on port {int} does not support TLS OCSP stapling")
  public void assertTlsOcspStaplingNotSupported(String host, int port) {
    runTlsOcspStaplingProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.FAILED.name());
  }

  /**
   * Executes the unknown-extension probe and asserts that the target tolerates unknown extensions.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} toleriert unbekannte TLS Extensions")
  @Then("TGR assert host {tigerResolvedString} on port {int} tolerates unknown TLS extensions")
  public void assertTlsUnknownExtensionsTolerated(String host, int port) {
    runTlsUnknownExtensionProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.PASSED.name());
  }

  /**
   * Executes the unknown-extension probe and asserts that the target rejects unknown extensions.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} lehnt unbekannte TLS Extensions ab")
  @Then("TGR assert host {tigerResolvedString} on port {int} rejects unknown TLS extensions")
  public void assertTlsUnknownExtensionsRejected(String host, int port) {
    runTlsUnknownExtensionProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.FAILED.name());
  }

  /**
   * Executes the malformed-record probe and asserts that the target rejects malformed TLS input.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   */
  @Dann("TGR prüfe Host {tigerResolvedString} auf Port {int} lehnt malformed TLS Records ab")
  @Then("TGR assert host {tigerResolvedString} on port {int} rejects malformed TLS records")
  public void assertMalformedTlsRecordsRejected(String host, int port) {
    runTlsMalformedRecordProbe(host, port);
    assertLastTlsBehaviorProbeVerdict(TlsTestVerdict.PASSED.name());
  }

  /**
   * Returns the last executed profile-based TLS report.
   *
   * @return current TLS profile report
   */
  private TlsTestReport currentReport() {
    if (lastTlsTestReport == null) {
      throw new TigerTlsTestsGlueException(
          "No TLS test report available yet. Run a TLS profile first.");
    }
    return lastTlsTestReport;
  }

  /**
   * Returns the last executed TLS protocol scan report.
   *
   * @return current TLS protocol scan report
   */
  private TlsFeatureSupportReport currentProtocolScanReport() {
    if (lastTlsProtocolScanReport == null) {
      throw new TigerTlsTestsGlueException(
          "No TLS protocol scan report available yet. Run a TLS protocol scan first.");
    }
    return lastTlsProtocolScanReport;
  }

  /**
   * Returns the last executed TLS cipher-suite scan report.
   *
   * @return current TLS cipher-suite scan report
   */
  private TlsFeatureSupportReport currentCipherSuiteScanReport() {
    if (lastTlsCipherSuiteScanReport == null) {
      throw new TigerTlsTestsGlueException(
          "No TLS cipher suite scan report available yet. Run a TLS cipher suite scan first.");
    }
    return lastTlsCipherSuiteScanReport;
  }

  /**
   * Returns the last executed TLS application-protocol scan report.
   *
   * @return current TLS application-protocol scan report
   */
  private TlsFeatureSupportReport currentApplicationProtocolScanReport() {
    if (lastTlsApplicationProtocolScanReport == null) {
      throw new TigerTlsTestsGlueException(
          "No TLS application protocol scan report available yet. Run a TLS application protocol scan first.");
    }
    return lastTlsApplicationProtocolScanReport;
  }

  /**
   * Returns the last executed TLS named-group scan report.
   *
   * @return current TLS named-group scan report
   */
  private TlsFeatureSupportReport currentNamedGroupScanReport() {
    if (lastTlsNamedGroupScanReport == null) {
      throw new TigerTlsTestsGlueException(
          "No TLS named group scan report available yet. Run a TLS named group scan first.");
    }
    return lastTlsNamedGroupScanReport;
  }

  /**
   * Returns the last executed TLS signature-scheme scan report.
   *
   * @return current TLS signature-scheme scan report
   */
  private TlsFeatureSupportReport currentSignatureSchemeScanReport() {
    if (lastTlsSignatureSchemeScanReport == null) {
      throw new TigerTlsTestsGlueException(
          "No TLS signature scheme scan report available yet. Run a TLS signature scheme scan first.");
    }
    return lastTlsSignatureSchemeScanReport;
  }

  /**
   * Returns the last executed TLS behavior probe report.
   *
   * @return current TLS behavior probe report
   */
  private TlsBehaviorProbeReport currentBehaviorProbeReport() {
    if (lastTlsBehaviorProbeReport == null) {
      throw new TigerTlsTestsGlueException(
          "No TLS behavior probe report available yet. Run a TLS behavior probe first.");
    }
    return lastTlsBehaviorProbeReport;
  }

  /**
   * Returns the running TLS server observation handle.
   *
   * @return running TLS server observation handle
   */
  private TlsServerObservationHandle currentServerObservationHandle() {
    if (lastTlsServerObservationHandle == null) {
      throw new TigerTlsTestsGlueException(
          "No running TLS server observation available yet. Start a TLS server observation first.");
    }
    return lastTlsServerObservationHandle;
  }

  /**
   * Returns the last completed TLS server observation report.
   *
   * @return completed TLS server observation report
   */
  private TlsServerObservationReport currentServerObservationReport() {
    if (lastTlsServerObservationReport == null) {
      throw new TigerTlsTestsGlueException(
          "No TLS server observation report available yet. Await a TLS server observation first.");
    }
    return lastTlsServerObservationReport;
  }

  /**
   * Resets the reusable TLS execution settings to their defaults.
   */
  private void resetExecutionConfiguration() {
    closeLastObservationHandleQuietly();
    tlsConnectionConfiguration = TlsConnectionConfiguration.defaults();
    tlsServerConnectionConfiguration = TlsServerConnectionConfiguration.defaults();
    lastTlsServerObservationHandle = null;
    lastTlsServerObservationReport = null;
    configuredSniHostName = null;
  }

  /**
   * Applies an immutable update to the reusable TLS execution settings.
   *
   * @param configurationUpdater immutable configuration updater
   */
  private void updateConnectionConfiguration(
      UnaryOperator<TlsConnectionConfiguration> configurationUpdater) {
    tlsConnectionConfiguration = configurationUpdater.apply(tlsConnectionConfiguration);
  }

  /**
   * Applies an immutable update to the reusable TLS server-observation settings.
   *
   * @param configurationUpdater immutable server configuration updater
   */
  private void updateServerConnectionConfiguration(
      UnaryOperator<TlsServerConnectionConfiguration> configurationUpdater) {
    tlsServerConnectionConfiguration =
        configurationUpdater.apply(tlsServerConnectionConfiguration);
  }

  /**
   * Closes the last running TLS server observation handle while suppressing secondary close
   * failures.
   */
  private void closeLastObservationHandleQuietly() {
    if (lastTlsServerObservationHandle == null) {
      return;
    }
    try {
      lastTlsServerObservationHandle.close();
    } catch (Exception e) {
      log.debug("Ignoring TLS server observation close failure", e);
    } finally {
      lastTlsServerObservationHandle = null;
    }
  }

  /**
   * Executes the connectivity profile with a temporary connection configuration override.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   * @param effectiveConfiguration effective connection configuration for this probe
   * @return connectivity report
   */
  private TlsTestReport runConnectivityProbe(
      String host, int port, TlsConnectionConfiguration effectiveConfiguration) {
    return runTlsTestProfile(TlsTestProfile.CONNECTIVITY, host, port, effectiveConfiguration);
  }

  /**
   * Executes one TLS profile with an explicit connection configuration.
   *
   * @param profile TLS profile to execute
   * @param host target host name or IP address
   * @param port target TCP port
   * @param effectiveConfiguration effective connection configuration for this execution
   * @return TLS test report
   */
  private TlsTestReport runTlsTestProfile(
      TlsTestProfile profile, String host, int port, TlsConnectionConfiguration effectiveConfiguration) {
    log.info("Running TLS profile {} against {}:{}", profile, host, port);
    final TlsTestTarget target = buildTarget(host, port);
    return tlsTestRunner.run(new TlsTestRequest(target, profile, effectiveConfiguration));
  }

  /**
   * Builds the effective TLS target, applying the configured SNI override when present.
   *
   * @param host target host name or IP address
   * @param port target TCP port
   * @return effective TLS target
   */
  private TlsTestTarget buildTarget(String host, int port) {
    return configuredSniHostName == null
        ? new TlsTestTarget(host, port)
        : new TlsTestTarget(host, port, configuredSniHostName);
  }

  /**
   * Parses a comma-separated token list.
   *
   * @param tokens raw comma-separated tokens
   * @param description human-readable token list description
   * @return parsed token list
   */
  private List<String> parseTokenList(String tokens, String description) {
    final List<String> parsedTokens =
        Arrays.stream(tokens.split(","))
            .map(String::trim)
            .filter(token -> !token.isEmpty())
            .toList();
    if (parsedTokens.isEmpty()) {
      throw new TigerTlsTestsGlueException(description + " must not be blank");
    }
    return parsedTokens;
  }

  /**
   * Parses one required token.
   *
   * @param token raw token
   * @param description human-readable token description
   * @return normalized token
   */
  private String parseSingleToken(String token, String description) {
    final String normalizedToken = token == null ? "" : token.trim();
    if (normalizedToken.isEmpty()) {
      throw new TigerTlsTestsGlueException(description + " must not be blank");
    }
    return normalizedToken;
  }

  /**
   * Extracts the session summary from one successful TLS test result.
   *
   * @param result TLS test result
   * @return negotiated session summary
   */
  private de.gematik.test.tiger.tlstests.TlsSessionSummary extractSessionSummary(
      de.gematik.test.tiger.tlstests.TlsTestResult result) {
    if (result.sessionSummary() == null) {
      throw new TigerTlsTestsGlueException(
          "TLS test %s did not produce a successful handshake summary"
              .formatted(result.testCase().token()));
    }
    return result.sessionSummary();
  }

  /**
   * Resolves one result from the last TLS profile report.
   *
   * @param testCaseToken test case token to resolve
   * @return matching TLS profile result
   */
  private de.gematik.test.tiger.tlstests.TlsTestResult currentProfileResult(String testCaseToken) {
    return currentReport()
        .findResult(TlsTestCase.fromToken(testCaseToken))
        .orElseThrow(
            () ->
                new TigerTlsTestsGlueException(
                    "No TLS profile result available for " + testCaseToken));
  }

  /**
   * Resolves one result from the last TLS protocol scan.
   *
   * @param protocol protocol token to resolve
   * @return matching protocol scan result
   */
  private TlsFeatureSupportResult currentProtocolScanResult(String protocol) {
    return currentProtocolScanReport()
        .findResult(parseSingleToken(protocol, "TLS protocol"))
        .orElseThrow(
            () ->
                new TigerTlsTestsGlueException(
                    "No TLS protocol scan result available for " + protocol));
  }

  /**
   * Resolves one result from the last TLS cipher-suite scan.
   *
   * @param cipherSuite cipher-suite token to resolve
   * @return matching cipher-suite scan result
   */
  private TlsFeatureSupportResult currentCipherSuiteScanResult(String cipherSuite) {
    return currentCipherSuiteScanReport()
        .findResult(parseSingleToken(cipherSuite, "TLS cipher suite"))
        .orElseThrow(
            () ->
                new TigerTlsTestsGlueException(
                    "No TLS cipher-suite scan result available for " + cipherSuite));
  }

  /**
   * Resolves one result from the last TLS application-protocol scan.
   *
   * @param applicationProtocol application-protocol token to resolve
   * @return matching application-protocol scan result
   */
  private TlsFeatureSupportResult currentApplicationProtocolScanResult(String applicationProtocol) {
    return currentApplicationProtocolScanReport()
        .findResult(parseSingleToken(applicationProtocol, "TLS application protocol"))
        .orElseThrow(
            () ->
                new TigerTlsTestsGlueException(
                    "No TLS application-protocol scan result available for "
                        + applicationProtocol));
  }

  /**
   * Resolves one result from the last TLS named-group scan.
   *
   * @param namedGroup named-group token to resolve
   * @return matching named-group scan result
   */
  private TlsFeatureSupportResult currentNamedGroupScanResult(String namedGroup) {
    return currentNamedGroupScanReport()
        .findResult(parseSingleToken(namedGroup, "TLS named group"))
        .orElseThrow(
            () ->
                new TigerTlsTestsGlueException(
                    "No TLS named-group scan result available for " + namedGroup));
  }

  /**
   * Resolves one result from the last TLS signature-scheme scan.
   *
   * @param signatureScheme signature-scheme token to resolve
   * @return matching signature-scheme scan result
   */
  private TlsFeatureSupportResult currentSignatureSchemeScanResult(String signatureScheme) {
    return currentSignatureSchemeScanReport()
        .findResult(parseSingleToken(signatureScheme, "TLS signature scheme"))
        .orElseThrow(
            () ->
                new TigerTlsTestsGlueException(
                    "No TLS signature-scheme scan result available for " + signatureScheme));
  }

  /**
   * Returns the negotiated session summary of the last TLS server observation.
   *
   * @return negotiated session summary of the last TLS server observation
   */
  private de.gematik.test.tiger.tlstests.TlsSessionSummary currentServerObservationSessionSummary() {
    final TlsServerObservationReport report = currentServerObservationReport();
    if (report.sessionSummary() == null) {
      throw new TigerTlsTestsGlueException(
          "The last TLS server observation did not complete a successful handshake");
    }
    return report.sessionSummary();
  }

  /**
   * Parses a TLS verdict token.
   *
   * @param verdictToken raw verdict token
   * @return parsed TLS verdict
   */
  private TlsTestVerdict parseVerdict(String verdictToken) {
    try {
      return TlsTestVerdict.valueOf(verdictToken.trim().toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new TigerTlsTestsGlueException("Unknown TLS verdict token: " + verdictToken, e);
    }
  }

  /**
   * Internal glue exception used for invalid TLS step usage.
   */
  private static final class TigerTlsTestsGlueException extends RuntimeException {

    /**
     * Creates an exception with a message.
     *
     * @param message failure message
     */
    TigerTlsTestsGlueException(String message) {
      super(message);
    }

    /**
     * Creates an exception with a message and cause.
     *
     * @param message failure message
     * @param cause root cause
     */
    TigerTlsTestsGlueException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
