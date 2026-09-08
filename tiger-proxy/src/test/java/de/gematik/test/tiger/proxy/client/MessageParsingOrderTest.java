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
package de.gematik.test.tiger.proxy.client;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.rbellogger.RbelConversionPhase;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.test.tiger.common.RingBufferHashMap;
import de.gematik.test.tiger.common.RingBufferHashSet;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.SneakyThrows;
import lombok.val;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests for {@link TigerRemoteProxyClient#scheduleAfterMessage}: when may a message be parsed while
 * the message it was recorded after is not in the history yet?
 *
 * <p>Every test follows the same shape - put the predecessor into one state, queue a task behind
 * it, optionally trigger a transition, then observe whether the task was released. The
 * predecessor's state is the only real variable, so it is what the {@code givenPredecessor…}
 * methods below name.
 *
 * <p>These tests run without a Spring context but against a real {@link TigerRemoteProxyClient},
 * including its converter and its scheduler. The queued parse task is stood in for by a latch, so
 * what is asserted is the release, not the parsing itself.
 */
class MessageParsingOrderTest {

  /** Long enough that the previous-message timeout cannot interfere with what a test observes. */
  private static final Duration TIMEOUT_NOT_UNDER_TEST = Duration.ofSeconds(5);

  /** Short enough to watch the previous-message timeout fire without slowing the suite down. */
  private static final Duration SHORT_TIMEOUT = Duration.ofMillis(500);

  /** Grants an expected release enough room to happen on a loaded machine. */
  private static final Duration RELEASE_WINDOW = Duration.ofSeconds(2);

  /** How long a task is watched before it counts as still waiting. */
  private static final Duration WAITING_OBSERVATION = Duration.ofMillis(200);

  /** Lets every partial message count as expired the moment it is looked at. */
  private static final Duration EXPIRE_IMMEDIATELY = Duration.ZERO;

  /** Keeps the periodic cleanup from expiring anything while a test is watching. */
  private static final Duration NEVER_EXPIRES = Duration.ofHours(1);

  /** Comfortably longer than {@link #WAITING_OBSERVATION}, so the two never race. */
  private static final Duration PARTIAL_MESSAGE_AGE = Duration.ofSeconds(1);

  private static final byte[] PREDECESSOR_CONTENT = "X".getBytes(StandardCharsets.UTF_8);

  private static final String PREDECESSOR = "predecessor-uuid";

  private TigerRemoteProxyClient client;
  private CountDownLatch releasedTasks;
  private final AtomicInteger executions = new AtomicInteger();
  private final AtomicInteger successorCount = new AtomicInteger();

  @AfterEach
  void tearDown() {
    if (client != null) {
      client.close();
    }
  }

  @Nested
  @DisplayName("Release by the state of the predecessor")
  class PredecessorState {

    @Test
    @DisplayName("A predecessor that is already parsed releases its successor immediately")
    void predecessorParsed_releasesImmediately() {
      givenClient(TIMEOUT_NOT_UNDER_TEST);
      val predecessor = givenPredecessorParsed(PREDECESSOR);

      queueBehind(PREDECESSOR);

      assertReleasedWithin(RELEASE_WINDOW);
      assertThat(predecessor.hasFacet(TigerRemoteProxyClient.NextMessageParsedFacet.class))
          .as("the parsed predecessor should be marked as having a parsed successor")
          .isTrue();
    }

    @Test
    @DisplayName(
        "A predecessor that was removed from the history releases its successor immediately")
    void predecessorRemoved_releasesImmediatelyAndForgetsTheUuid() {
      givenClient(TIMEOUT_NOT_UNDER_TEST);
      givenPredecessorRemovedFromHistory(PREDECESSOR);

      queueBehind(PREDECESSOR);

      assertReleasedWithin(RELEASE_WINDOW);
      assertThat(removedMessageUuids().contains(PREDECESSOR))
          .as("the UUID should be forgotten once its successor no longer needs it")
          .isFalse();
    }

    @Test
    @DisplayName("A predecessor that is being parsed holds its successor back until it completes")
    void predecessorBeingParsed_waitsUntilCompleted() {
      givenClient(TIMEOUT_NOT_UNDER_TEST);
      givenPredecessorBeingParsed(PREDECESSOR);

      queueBehind(PREDECESSOR);
      assertStillWaitingAfter(WAITING_OBSERVATION);

      whenPredecessorCompletes(PREDECESSOR);

      assertReleasedWithin(RELEASE_WINDOW);
    }

    @Test
    @DisplayName("Completing the predecessor releases the queued successor")
    void predecessorCompletes_releasesQueuedSuccessor() {
      givenClient(TIMEOUT_NOT_UNDER_TEST);

      queueBehind(PREDECESSOR);
      assertStillWaitingAfter(WAITING_OBSERVATION);

      whenPredecessorCompletes(PREDECESSOR);

      assertReleasedWithin(RELEASE_WINDOW);
      assertNoTasksWaitingFor(PREDECESSOR);
    }

    @Test
    @DisplayName("Completing the predecessor releases every successor exactly once")
    void predecessorCompletes_releasesEverySuccessorExactlyOnce() {
      givenClient(TIMEOUT_NOT_UNDER_TEST);
      val successors = 5;

      queueBehind(PREDECESSOR, successors);

      whenPredecessorCompletes(PREDECESSOR);

      assertReleasedWithin(RELEASE_WINDOW);
      assertThat(executions)
          .as("every queued task should have run exactly once")
          .hasValue(successors);
      assertNoTasksWaitingFor(PREDECESSOR);
    }
  }

  @Nested
  @DisplayName("Release by the timestamp of the predecessor")
  class PredecessorTimestamp {

    @Test
    @DisplayName("A predecessor recorded before this connection started will not arrive any more")
    void predecessorPredatesConnection_releasesImmediately() {
      givenClient(TIMEOUT_NOT_UNDER_TEST);
      val connectionStart = givenConnectionStartedAgo(Duration.ofMinutes(1));

      queueBehind(PREDECESSOR, connectionStart.minusMinutes(5));

      assertReleasedWithin(RELEASE_WINDOW);
    }

    @Test
    @DisplayName("A long gap between the predecessor and a young connection ends the wait")
    void predecessorLongBeforeYoungConnection_releasesImmediately() {
      givenClient(TIMEOUT_NOT_UNDER_TEST);
      givenConnectionStartedAgo(Duration.ofSeconds(30));

      queueBehind(PREDECESSOR, ZonedDateTime.now().minusMinutes(2));

      assertReleasedWithin(RELEASE_WINDOW);
    }

    @Test
    @DisplayName("A predecessor within the grace period is still waited for")
    void predecessorWithinGracePeriod_keepsWaiting() {
      givenClient(TIMEOUT_NOT_UNDER_TEST);
      val connectionStart = givenConnectionStartedAgo(Duration.ofSeconds(20));

      // 5 seconds before the connection started is well inside the 10 second grace period
      queueBehind(PREDECESSOR, connectionStart.minusSeconds(5));

      assertStillWaitingAfter(WAITING_OBSERVATION);
    }

    @Test
    @DisplayName("Without a predecessor timestamp the wait ends on the timeout")
    void noPredecessorTimestamp_releasesOnTimeout() {
      givenClient(SHORT_TIMEOUT);
      givenConnectionStartedAgo(Duration.ofSeconds(10));

      queueBehind(PREDECESSOR, null);

      assertStillWaitingAfter(WAITING_OBSERVATION);
      assertReleasedWithin(RELEASE_WINDOW);
    }

    @Test
    @DisplayName("Without a connection start time the wait ends on the timeout")
    void noConnectionStartTime_releasesOnTimeout() {
      givenClient(SHORT_TIMEOUT);

      queueBehind(PREDECESSOR, ZonedDateTime.now().minusMinutes(5));

      assertStillWaitingAfter(WAITING_OBSERVATION);
      assertReleasedWithin(RELEASE_WINDOW);
    }
  }

  @Nested
  @DisplayName("Release when the predecessor is given up on")
  class AbandonedPredecessor {

    @Test
    @DisplayName("Cleaning up a half-received predecessor releases its successor")
    void halfReceivedPredecessorCleanedUp_releasesSuccessor() {
      givenClient(TIMEOUT_NOT_UNDER_TEST, NEVER_EXPIRES);
      givenPredecessorHalfReceived(PREDECESSOR);

      queueBehind(PREDECESSOR);
      assertStillWaitingAfter(WAITING_OBSERVATION);
      assertThat(client.getMessageAssembler().snapshot())
          .as("nothing may expire before the cleanup under test runs")
          .containsKey(PREDECESSOR);

      client.getMessageAssembler().setMaximumMessageAge(EXPIRE_IMMEDIATELY);
      client.getMessageAssembler().removeExpiredMessages();

      assertReleasedWithin(RELEASE_WINDOW);
      assertThat(client.getMessageAssembler().snapshot()).doesNotContainKey(PREDECESSOR);
      assertThat(knownMessageUuidsContain(PREDECESSOR))
          .as("the UUID reservation should be dropped so the message can be received again")
          .isFalse();
    }

    @Test
    @DisplayName("A half-received predecessor releases its successor when it ages out")
    void halfReceivedPredecessorAgesOut_releasesSuccessorWithoutCleanup() {
      givenClient(SHORT_TIMEOUT, PARTIAL_MESSAGE_AGE);
      givenPredecessorHalfReceived(PREDECESSOR);

      queueBehind(PREDECESSOR);

      assertStillWaitingAfter(WAITING_OBSERVATION);
      assertReleasedWithin(RELEASE_WINDOW);
    }
  }

  // ---------------------------------------------------------------- fixture

  private void givenClient(Duration previousMessageTimeout) {
    client =
        new TigerRemoteProxyClient(
            "http://localhost:0",
            TigerProxyConfiguration.builder()
                .downloadInitialTrafficFromEndpoints(false)
                .waitForPreviousMessageBeforeParsingInSeconds(inSeconds(previousMessageTimeout))
                .proxyLogLevel("WARN")
                .build());
  }

  private void givenClient(Duration previousMessageTimeout, Duration maximumPartialMessageAge) {
    givenClient(previousMessageTimeout);
    client.getMessageAssembler().setMaximumMessageAge(maximumPartialMessageAge);
  }

  private static float inSeconds(Duration duration) {
    return duration.toMillis() / 1000f;
  }

  // ------------------------------------------------------ predecessor states

  /** The predecessor is in the history and fully converted. */
  private RbelElement givenPredecessorParsed(String uuid) {
    val predecessor = RbelElement.builder().uuid(uuid).rawContent(PREDECESSOR_CONTENT).build();
    predecessor.setConversionPhase(RbelConversionPhase.COMPLETED);
    client.getRbelLogger().getRbelConverter().addMessageToHistory(predecessor);
    return predecessor;
  }

  /** The predecessor was parsed once but has since been dropped from the history. */
  private void givenPredecessorRemovedFromHistory(String uuid) {
    removedMessageUuids().add(uuid);
  }

  /** The predecessor has been received completely and its conversion is under way. */
  private void givenPredecessorBeingParsed(String uuid) {
    client.getRbelLogger().getRbelConverter().getKnownMessageUuids().add(uuid);
  }

  /** Some parts of the predecessor arrived, the rest never does. */
  private void givenPredecessorHalfReceived(String uuid) {
    client.getMessageAssembler().receiveMetadata(uuid, PartialTracingMessage.builder().build());
  }

  private ZonedDateTime givenConnectionStartedAgo(Duration age) {
    val connectionStart = ZonedDateTime.now().minus(age);
    client.getWebSocketConnectionStartTime().set(connectionStart);
    return connectionStart;
  }

  // ------------------------------------------------------------------ acting

  private void queueBehind(String previousMessageUuid) {
    queueBehind(previousMessageUuid, 1);
  }

  private void queueBehind(String previousMessageUuid, int successors) {
    releasedTasks = new CountDownLatch(successors);
    for (int i = 0; i < successors; i++) {
      client.scheduleAfterMessage(previousMessageUuid, this::taskWasReleased, nextSuccessorUuid());
    }
  }

  private void queueBehind(String previousMessageUuid, ZonedDateTime previousMessageTimestamp) {
    releasedTasks = new CountDownLatch(1);
    client.scheduleAfterMessage(
        previousMessageUuid, this::taskWasReleased, nextSuccessorUuid(), previousMessageTimestamp);
  }

  private void whenPredecessorCompletes(String uuid) {
    client.signalNewCompletedMessage(givenPredecessorParsed(uuid));
  }

  private void taskWasReleased() {
    executions.incrementAndGet();
    releasedTasks.countDown();
  }

  private String nextSuccessorUuid() {
    return "successor-uuid-" + successorCount.incrementAndGet();
  }

  // -------------------------------------------------------------- assertions

  private void assertReleasedWithin(Duration timeout) {
    assertThat(awaitRelease(timeout))
        .as("every queued task should have been released within %s", timeout)
        .isTrue();
  }

  private void assertStillWaitingAfter(Duration duration) {
    assertThat(awaitRelease(duration))
        .as("the queued task should still be waiting after %s", duration)
        .isFalse();
  }

  @SneakyThrows
  private boolean awaitRelease(Duration duration) {
    return releasedTasks.await(duration.toMillis(), TimeUnit.MILLISECONDS);
  }

  private void assertNoTasksWaitingFor(String previousMessageUuid) {
    assertThat(parsingTasksWaitingForUuid().get(previousMessageUuid))
        .as("no task should be left waiting for %s", previousMessageUuid)
        .isEmpty();
  }

  private boolean knownMessageUuidsContain(String uuid) {
    return client.getRbelLogger().getRbelConverter().getKnownMessageUuids().contains(uuid);
  }

  // ------------------------------------------- internals without an accessor

  @SuppressWarnings("unchecked")
  private RingBufferHashSet<String> removedMessageUuids() {
    return (RingBufferHashSet<String>) ReflectionTestUtils.getField(client, "removedMessageUuids");
  }

  @SuppressWarnings("unchecked")
  private RingBufferHashMap<String, List<Runnable>> parsingTasksWaitingForUuid() {
    return (RingBufferHashMap<String, List<Runnable>>)
        ReflectionTestUtils.getField(client, "parsingTasksWaitingForUuid");
  }
}
