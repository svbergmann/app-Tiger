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
package io.cucumber.core.plugin;

import static io.cucumber.junit.platform.engine.Constants.EXECUTION_DRY_RUN_PROPERTY_NAME;
import static org.awaitility.Awaitility.await;

import de.gematik.test.tiger.lib.TigerDirector;
import de.gematik.test.tiger.testenvmgr.api.model.mapper.TigerTestIdentifier;
import de.gematik.test.tiger.testenvmgr.data.TestSuiteLifecycle;
import de.gematik.test.tiger.testenvmgr.env.ScenarioRunner;
import de.gematik.test.tiger.testenvmgr.env.TigerStatusUpdate;
import de.gematik.test.tiger.testenvmgr.util.ScenarioCollector;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

/**
 * We register this listener to save the scenarios that are found by the cucumber engine. The main
 * purpose of finding them, is that we then get unique TestIdentifiers that make it much easier to
 * rerun tests. See
 * de.gematik.test.tiger.testenvmgr.env.ScenarioRunner#runTest(org.junit.platform.launcher.TestIdentifier)
 */
@Slf4j
@NoArgsConstructor
public class TigerExecutionListener implements TestExecutionListener {

  /** Width chosen to keep progress lines compact in Maven and CI consoles. */
  private static final int PROGRESS_BAR_WIDTH = 20;

  private boolean isATigerTest;

  /** Number of scenario variants to report, or zero when progress reporting is disabled. */
  private int totalScenarios;

  /** Thread-safe because JUnit may execute scenarios concurrently. */
  private final AtomicInteger completedScenarios = new AtomicInteger();

  @Override
  public void testPlanExecutionStarted(TestPlan testPlan) {
    totalScenarios = 0;
    isATigerTest = TigerDirector.isInitialized();
    if (!isATigerTest) {
      return;
    }
    // The scenario collection is also the source for the feature selector, so the console and UI
    // always count the same selected scenario variants.
    var tigerScenarios = ScenarioCollector.collectTigerScenarios(testPlan);
    ScenarioRunner.addTigerScenarios(tigerScenarios);
    totalScenarios =
        testPlan
                .getConfigurationParameters()
                .getBoolean(EXECUTION_DRY_RUN_PROPERTY_NAME)
                .orElse(false)
            ? 0
            : tigerScenarios.size();
    completedScenarios.set(0);
    if (totalScenarios > 0) {
      log.info(formatProgress(0, totalScenarios));
    }
  }

  /** Updates the console progress bar after each selected Cucumber scenario variant completes. */
  @Override
  public void executionFinished(
      TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
    if (totalScenarios > 0
        && testIdentifier.isTest()
        && testIdentifier.getUniqueIdObject().getSegments().stream()
            .anyMatch(
                segment ->
                    segment.getType().equals("engine") && segment.getValue().equals("cucumber"))) {
      log.info(formatProgress(completedScenarios.incrementAndGet(), totalScenarios));
    }
  }

  @Override
  public void testPlanExecutionFinished(TestPlan testPlan) {
    if (!isATigerTest) {
      return;
    }
    TigerDirector.getTigerTestEnvMgr()
        .receiveTestEnvUpdate(
            TigerStatusUpdate.builder().testSuiteLifecycle(TestSuiteLifecycle.IDLE).build());
    testPlan
        .getConfigurationParameters()
        .getBoolean(EXECUTION_DRY_RUN_PROPERTY_NAME)
        .ifPresent(
            dryRun -> {
              if (dryRun) {
                log.debug("Dry run detected. Will wait for tiger shutdown");
                await()
                    .logging(log::trace)
                    .pollInterval(1, TimeUnit.SECONDS)
                    .atMost(
                        TigerDirector.getLibConfig().getPauseExecutionTimeoutSeconds(),
                        TimeUnit.SECONDS)
                    .until(() -> TigerDirector.getTigerTestEnvMgr().isShutDown());
              }
            });
  }

  @Override
  public void dynamicTestRegistered(TestIdentifier testIdentifier) {
    if (!isATigerTest) {
      return;
    }
    if (testIdentifier.isTest()) {
      ScenarioRunner.addTigerScenarios(
          List.of(new TigerTestIdentifier(testIdentifier, testIdentifier.getDisplayName())));
    }
  }

  /**
   * Formats a fixed-width progress bar that remains readable in interactive terminals and CI logs.
   *
   * @param completed number of completed scenario variants
   * @param total total number of selected scenario variants
   * @return the human-readable progress line
   */
  static String formatProgress(int completed, int total) {
    int filled = completed * PROGRESS_BAR_WIDTH / total;
    return "Tiger test progress: [%s%s] %d/%d (%d%%)"
        .formatted(
            "=".repeat(filled),
            " ".repeat(PROGRESS_BAR_WIDTH - filled),
            completed,
            total,
            completed * 100 / total);
  }
}
