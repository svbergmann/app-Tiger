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
package de.gematik.rbellogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import de.gematik.rbellogger.configuration.RbelConfiguration;
import de.gematik.rbellogger.data.RbelElement;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The waiting methods block a caller until conversion has caught up. Getting them wrong is
 * expensive in both directions: waiting for something already finished stalls for the full 100s
 * timeout, and not waiting hands out a half-converted tree.
 *
 * <p>Every test is bounded so a regression fails fast instead of sitting on that timeout.
 */
class RbelMessageHistoryWaitTest {

  private static final Duration SHOULD_BE_IMMEDIATE = Duration.ofSeconds(5);

  private RbelMessageHistory history;
  private ExecutorService pool;

  @BeforeEach
  void setUp() {
    history = RbelLogger.build(new RbelConfiguration()).getRbelConverter().getHistory();
    pool = Executors.newSingleThreadExecutor();
  }

  @AfterEach
  void tearDown() {
    pool.shutdownNow();
  }

  @Test
  void shouldReturnAtOnceForAnAlreadyFinishedElement() {
    var finished = addMessage(RbelConversionPhase.COMPLETED);

    assertTimeoutPreemptively(
        SHOULD_BE_IMMEDIATE, () -> history.waitForGivenElementToBeParsed(finished));
  }

  @Test
  void shouldReturnAtOnceWhenNothingIsUnfinished() {
    addMessage(RbelConversionPhase.COMPLETED);

    assertTimeoutPreemptively(
        SHOULD_BE_IMMEDIATE, () -> history.waitForAllCurrentMessagesToBeParsed());
  }

  @Test
  void shouldReturnAtOnceWhenTheHistoryIsEmpty() {
    assertTimeoutPreemptively(
        SHOULD_BE_IMMEDIATE, () -> history.waitForAllCurrentMessagesToBeParsed());
  }

  @Test
  void shouldWaitForAnUnfinishedElementUntilItIsSignalled() throws Exception {
    var unfinished = addMessage(RbelConversionPhase.CONTENT_PARSING);
    var waiterStarted = new CountDownLatch(1);

    var waiting =
        pool.submit(
            () -> {
              waiterStarted.countDown();
              history.waitForGivenElementToBeParsed(unfinished);
              return true;
            });

    assertThat(waiterStarted.await(5, TimeUnit.SECONDS)).isTrue();
    assertThat(waiting.isDone())
        .as("must still be waiting while conversion is unfinished")
        .isFalse();

    unfinished.setConversionPhase(RbelConversionPhase.COMPLETED);
    history.signalMessageParsingIsComplete(unfinished);

    assertThat(waiting.get(5, TimeUnit.SECONDS)).isTrue();
  }

  /**
   * Only the messages ahead of the given one are waited for. A later message that is still
   * converting must not hold the caller up - that is the whole point of the sequence-number cut.
   */
  @Test
  void shouldOnlyWaitForElementsPrecedingTheGivenOne() throws Exception {
    var earlier = addMessage(RbelConversionPhase.CONTENT_PARSING);
    var pivot = addMessage(RbelConversionPhase.CONTENT_PARSING);
    var later = addMessage(RbelConversionPhase.CONTENT_PARSING);

    var waiting = pool.submit(() -> history.waitForAllElementsBeforeGivenToBeParsed(pivot));

    earlier.setConversionPhase(RbelConversionPhase.COMPLETED);
    history.signalMessageParsingIsComplete(earlier);

    assertTimeoutPreemptively(
        SHOULD_BE_IMMEDIATE,
        () -> waiting.get(5, TimeUnit.SECONDS),
        "finishing the preceding message must release the wait, even though a later one is still"
            + " converting");
    assertThat(later.getConversionPhase().isFinished())
        .as("the later message was deliberately left unconverted")
        .isFalse();
  }

  private RbelElement addMessage(RbelConversionPhase phase) {
    var element =
        new RbelElement(RandomStringUtils.insecure().nextAlphanumeric(32).getBytes(), null);
    element.setConversionPhase(phase);
    history.addMessageToHistory(element, ZonedDateTime.now());
    return element;
  }
}
