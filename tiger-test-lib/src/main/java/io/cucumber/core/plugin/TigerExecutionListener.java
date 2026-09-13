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
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.UniqueId;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

/** Collects scenarios for Tiger's feature selector and reports their execution progress. */
@Slf4j
@NoArgsConstructor
public class TigerExecutionListener implements TestExecutionListener {

  private static final int BAR_WIDTH = 20;
  private final Set<UniqueId> pending = new HashSet<>();
  private int total;
  private int skipped;

  private boolean isATigerTest;

  @Override
  public void testPlanExecutionStarted(TestPlan testPlan) {
    isATigerTest = TigerDirector.isInitialized();
    var scenarios =
        isATigerTest
            ? ScenarioCollector.collectTigerScenarios(testPlan)
            : List.<TigerTestIdentifier>of();
    ScenarioRunner.addTigerScenarios(scenarios);
    startProgress(testPlan, scenarios);
  }

  @Override
  public void testPlanExecutionFinished(TestPlan testPlan) {
    if (!isATigerTest) {
      return;
    }
    finishProgress();
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

  synchronized void startProgress(TestPlan plan, Collection<TigerTestIdentifier> scenarios) {
    pending.clear();
    skipped = 0;
    var selection = new TigerScenarioSelection(plan);
    scenarios.stream()
        .map(TigerTestIdentifier::getTestIdentifier)
        .filter(selection)
        .map(TestIdentifier::getUniqueIdObject)
        .forEach(pending::add);
    total = pending.size();
    report();
  }

  @Override
  public synchronized void executionFinished(TestIdentifier test, TestExecutionResult result) {
    if (pending.remove(test.getUniqueIdObject())) {
      report();
    }
  }

  @Override
  public synchronized void executionSkipped(TestIdentifier test, String reason) {
    int before = pending.size();
    pending.removeIf(id -> id.hasPrefix(test.getUniqueIdObject()));
    if (before != pending.size()) {
      skipped += before - pending.size();
      report();
    }
  }

  synchronized void finishProgress() {
    if (!pending.isEmpty()) {
      log.warn(
          "{}; run ended with {} scenarios not executed",
          formatProgress(total - pending.size(), total),
          pending.size());
    }
  }

  private void report() {
    if (total > 0) {
      log.info(
          "{}{}",
          formatProgress(total - pending.size(), total),
          skipped == 0 ? "" : "; " + skipped + " skipped");
    }
  }

  /** Formats progress for a positive total and a completed count between zero and that total. */
  static String formatProgress(int completed, int total) {
    if (total <= 0 || completed < 0 || completed > total) {
      throw new IllegalArgumentException("Expected 0 <= completed <= total and total > 0");
    }
    int filled = (int) ((long) completed * BAR_WIDTH / total);
    return "Tiger test progress: [%s%s] %d/%d (%d%%)"
        .formatted(
            "=".repeat(filled),
            " ".repeat(BAR_WIDTH - filled),
            completed,
            total,
            (long) completed * 100 / total);
  }
}
