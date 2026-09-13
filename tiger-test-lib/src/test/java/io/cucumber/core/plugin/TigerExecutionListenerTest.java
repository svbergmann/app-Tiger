/*
 *
 * Copyright 2021-2026 gematik GmbH
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClasspathResource;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.cucumber.core.plugin.progress.ProgressSteps;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.UniqueId;
import org.junit.platform.engine.support.descriptor.AbstractTestDescriptor;
import org.junit.platform.launcher.*;
import org.junit.platform.launcher.core.*;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.suite.api.*;
import org.slf4j.LoggerFactory;

@org.junit.jupiter.api.parallel.Execution(org.junit.jupiter.api.parallel.ExecutionMode.SAME_THREAD)
class TigerExecutionListenerTest {
  private static final String FEATURE = "features/console-progress/progress.feature";
  private final TigerExecutionListener progress = new TigerExecutionListener();
  private final TestExecutionListener listener =
      new TestExecutionListener() {
        @Override
        public void testPlanExecutionStarted(TestPlan plan) {
          progress.startProgress(
              plan,
              de.gematik.test.tiger.testenvmgr.util.ScenarioCollector.collectTigerScenarios(plan));
        }

        @Override
        public void executionFinished(TestIdentifier test, TestExecutionResult result) {
          progress.executionFinished(test, result);
        }

        @Override
        public void executionSkipped(TestIdentifier test, String reason) {
          progress.executionSkipped(test, reason);
        }

        @Override
        public void testPlanExecutionFinished(TestPlan plan) {
          progress.finishProgress();
        }
      };
  private final Logger logger = (Logger) LoggerFactory.getLogger(TigerExecutionListener.class);
  private final ListAppender<ILoggingEvent> output = new ListAppender<>();

  @BeforeEach
  void prepare() {
    output.start();
    logger.addAppender(output);
    ProgressSteps.calls.set(0);
    ProgressSteps.failBeforeAll = false;
    ProgressSteps.failSteps = false;
    ProgressSteps.release = null;
  }

  @AfterEach
  void cleanup() {
    if (ProgressSteps.release != null) {
      ProgressSteps.release.countDown();
    }
    logger.detachAppender(output);
    output.stop();
  }

  @Test
  void formatsProgressWithoutIntegerOverflow() {
    assertThat(TigerExecutionListener.formatProgress(0, 4))
        .isEqualTo("Tiger test progress: [                    ] 0/4 (0%)");
    assertThat(TigerExecutionListener.formatProgress(1, 4))
        .isEqualTo("Tiger test progress: [=====               ] 1/4 (25%)");
    assertThat(TigerExecutionListener.formatProgress(4, 4))
        .isEqualTo("Tiger test progress: [====================] 4/4 (100%)");
    assertThat(TigerExecutionListener.formatProgress(Integer.MAX_VALUE, Integer.MAX_VALUE))
        .endsWith("(100%)");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> TigerExecutionListener.formatProgress(0, 0));
    assertThatIllegalArgumentException()
        .isThrownBy(() -> TigerExecutionListener.formatProgress(2, 1));
  }

  @Test
  void countsScenarioOutlineRowsAndResetsForReruns() {
    var launcher = launcher();
    var plan = launcher.discover(request().build());
    launcher.execute(plan, listener);
    assertThat(messages()).hasSize(4).last().asString().contains("3/3 (100%)");
    output.list.clear();
    launcher.execute(launcher.discover(request().build()), listener);
    assertThat(messages()).hasSize(4).first().asString().contains("0/3 (0%)");
    assertThat(messages()).last().asString().contains("3/3 (100%)");
  }

  @Test
  void excludesTagAndNameFilteredScenarios() {
    run(request().configurationParameter("cucumber.filter.tags", "@single"));
    assertThat(messages()).hasSize(2);
    assertThat(messages()).first().asString().contains("0/1 (0%)");
    assertThat(messages()).last().asString().contains("1/1 (100%)");
    output.list.clear();
    run(request().configurationParameter("cucumber.filter.name", "one"));
    assertThat(messages()).hasSize(2);
    assertThat(messages()).first().asString().contains("0/1 (0%)");
    assertThat(messages()).last().asString().contains("1/1 (100%)");
  }

  @Test
  void staysSilentForEmptySelectionsAndDryRuns() {
    run(request().configurationParameter("cucumber.filter.tags", "@absent"));
    run(request().filters(TagFilter.includeTags("absent")));
    run(request().configurationParameter("cucumber.execution.dry-run", "true"));
    run(suite(DrySuite.class));
    assertThat(ProgressSteps.calls).hasValue(0);
    assertThat(messages()).isEmpty();
  }

  @Test
  void respectsNestedSuiteExecutionModes() {
    run(suite(MixedSuite.class));
    assertThat(ProgressSteps.calls).hasValue(3);
    assertThat(messages()).last().asString().contains("3/3 (100%)");
  }

  @Test
  void countsFailuresAndExplainsContainerFailure() {
    ProgressSteps.failSteps = true;
    var summary = run(request());
    assertThat(summary.getSummary().getTestsFailedCount()).isEqualTo(3);
    assertThat(messages()).last().asString().contains("3/3 (100%)");
    output.list.clear();
    ProgressSteps.failBeforeAll = true;
    run(request());
    assertThat(messages())
        .hasSize(2)
        .last()
        .asString()
        .contains("0/3 (0%)", "3 scenarios not executed");
  }

  @Test
  void publishesParallelProgressInOrderWhileScenariosAreRunning() throws Exception {
    ProgressSteps.release = new CountDownLatch(1);
    var executor = Executors.newSingleThreadExecutor();
    try {
      var execution =
          executor.submit(
              () ->
                  run(
                      request()
                          .configurationParameter("cucumber.execution.parallel.enabled", "true")
                          .configurationParameter(
                              "cucumber.execution.parallel.config.strategy", "fixed")
                          .configurationParameter(
                              "cucumber.execution.parallel.config.fixed.parallelism", "3")));
      org.awaitility.Awaitility.await()
          .atMost(5, TimeUnit.SECONDS)
          .until(() -> messages().stream().anyMatch(m -> m.contains("2/3 (66%)")));
      ProgressSteps.release.countDown();
      execution.get(10, TimeUnit.SECONDS);
      assertThat(messages()).hasSize(4);
      assertThat(messages().get(1)).contains("1/3 (33%)");
      assertThat(messages().get(2)).contains("2/3 (66%)");
      assertThat(messages().get(3)).contains("3/3 (100%)");
    } finally {
      ProgressSteps.release.countDown();
      executor.shutdownNow();
    }
  }

  @Test
  void ignoresUnselectedTestsAndDuplicateFinishesAndKeepsTotalForSkippedContainers() {
    var plan = launcher().discover(request().build());
    listener.testPlanExecutionStarted(plan);
    var selected =
        de.gematik.test.tiger.testenvmgr.util.ScenarioCollector.collectTigerScenarios(plan);
    var cucumber =
        plan.getRoots().stream()
            .filter(root -> root.getUniqueId().equals("[engine:cucumber]"))
            .findFirst()
            .orElseThrow();
    progress.executionFinished(
        selected.iterator().next().getTestIdentifier(), TestExecutionResult.successful());
    progress.executionFinished(
        selected.iterator().next().getTestIdentifier(), TestExecutionResult.successful());
    progress.executionFinished(
        test(cucumber.getUniqueIdObject().append("scenario", "not-in-plan")),
        TestExecutionResult.successful());
    progress.executionFinished(
        test(UniqueId.forEngine("junit-jupiter").append("test", "one")),
        TestExecutionResult.successful());
    progress.executionSkipped(cucumber, "cancelled");
    progress.finishProgress();
    assertThat(messages()).hasSize(3).last().asString().contains("3/3 (100%)", "2 skipped");
  }

  @Test
  void appliesCompoundTagsAndExpandedOutlineNamesBeforeReporting() {
    run(request().configurationParameter("cucumber.filter.tags", "@feature and not @single"));
    assertThat(messages()).hasSize(3).first().asString().contains("0/2 (0%)");
    assertThat(messages()).last().asString().contains("2/2 (100%)");
    output.list.clear();
    run(
        request()
            .configurationParameter("cucumber.filter.name", "variants 2")
            .configurationParameter("cucumber.junit-platform.naming-strategy", "long"));
    assertThat(messages()).hasSize(2).first().asString().contains("0/1 (0%)");
    assertThat(messages()).last().asString().contains("1/1 (100%)");
  }

  @Test
  void usesSuiteResourcesAndCanOverrideParentDryRun() {
    run(suite(ResourceDrySuite.class));
    assertThat(messages()).isEmpty();
    run(suite(IndependentSuite.class).configurationParameter("cucumber.execution.dry-run", "true"));
    assertThat(ProgressSteps.calls).hasValue(3);
    output.list.clear();
    ProgressSteps.calls.set(0);
    run(suite(LiveSuite.class).configurationParameter("cucumber.execution.dry-run", "true"));
    assertThat(ProgressSteps.calls).hasValue(3);
    assertThat(messages()).hasSize(4).first().asString().contains("0/3 (0%)");
  }

  private static TestIdentifier test(UniqueId id) {
    return TestIdentifier.from(
        new AbstractTestDescriptor(id, "test") {
          @Override
          public Type getType() {
            return Type.TEST;
          }
        });
  }

  private List<String> messages() {
    synchronized (output) {
      return output.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }
  }

  private SummaryGeneratingListener run(LauncherDiscoveryRequestBuilder request) {
    var summary = new SummaryGeneratingListener();
    launcher().execute(request.build(), listener, summary);
    return summary;
  }

  private static LauncherDiscoveryRequestBuilder request() {
    return configuration()
        .selectors(selectClasspathResource(FEATURE))
        .filters(EngineFilter.includeEngines("cucumber"));
  }

  private static LauncherDiscoveryRequestBuilder suite(Class<?> suite) {
    return configuration().selectors(selectClass(suite));
  }

  private static LauncherDiscoveryRequestBuilder configuration() {
    return LauncherDiscoveryRequestBuilder.request()
        .configurationParameter("cucumber.glue", ProgressSteps.class.getPackageName());
  }

  private static Launcher launcher() {
    return LauncherFactory.create(
        LauncherConfig.builder()
            .enableTestExecutionListenerAutoRegistration(false)
            .enableLauncherDiscoveryListenerAutoRegistration(false)
            .enableLauncherSessionListenerAutoRegistration(false)
            .enablePostDiscoveryFilterAutoRegistration(false)
            .build());
  }

  @Suite
  @IncludeEngines("cucumber")
  @SelectClasspathResource(FEATURE)
  @ConfigurationParameter(key = "cucumber.execution.dry-run", value = "true")
  public static class DrySuite {}

  @Suite
  @IncludeEngines("cucumber")
  @SelectClasspathResource(FEATURE)
  @ConfigurationParameter(key = "cucumber.execution.dry-run", value = "false")
  public static class LiveSuite {}

  @Suite
  @IncludeEngines("cucumber")
  @SelectClasspathResource(FEATURE)
  @ConfigurationParametersResource("console-progress.properties")
  public static class ResourceDrySuite {}

  @Suite
  @IncludeEngines("cucumber")
  @SelectClasspathResource(FEATURE)
  @DisableParentConfigurationParameters
  @ConfigurationParameter(key = "cucumber.glue", value = "io.cucumber.core.plugin.progress")
  public static class IndependentSuite {}

  @Suite
  @SelectClasses({DrySuite.class, LiveSuite.class})
  public static class MixedSuite {}
}
