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
import de.gematik.test.tiger.common.util.TigerSerializationUtil;
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
import lombok.extern.slf4j.Slf4j;

/** TGR glue for running the built-in TLS test profiles against remote endpoints. */
@Slf4j
public class TigerTlsTestsGlue {

  private final TlsTestRunner tlsTestRunner;
  private TlsTestReport lastTlsTestReport;

  public TigerTlsTestsGlue() {
    this(new TlsTestRunner());
  }

  TigerTlsTestsGlue(TlsTestRunner tlsTestRunner) {
    this.tlsTestRunner = tlsTestRunner;
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
    log.info("Running TLS profile {} against {}:{}", profile, host, port);
    lastTlsTestReport =
        tlsTestRunner.run(TlsTestRequest.of(new TlsTestTarget(host, port), profile));
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

  private TlsTestReport currentReport() {
    if (lastTlsTestReport == null) {
      throw new TigerTlsTestsGlueException(
          "No TLS test report available yet. Run a TLS profile first.");
    }
    return lastTlsTestReport;
  }

  private TlsTestVerdict parseVerdict(String verdictToken) {
    try {
      return TlsTestVerdict.valueOf(verdictToken.trim().toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new TigerTlsTestsGlueException("Unknown TLS verdict token: " + verdictToken, e);
    }
  }

  private static final class TigerTlsTestsGlueException extends RuntimeException {
    TigerTlsTestsGlueException(String message) {
      super(message);
    }

    TigerTlsTestsGlueException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
