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

import de.gematik.rbellogger.KnownUuidsContainer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class PartialMessageAssemblerTest {

  private static final int STOP_WAITING_FOR_METADATA_AFTER_MS = 300;
  private static final int ANNOUNCED_PARTS = 2;
  private static final String UUID_UNDER_ASSEMBLY = "message-replaced-while-a-part-is-stored";
  private static final String FIRST_TO_ARRIVE = "first-to-arrive-then-restamped";
  private static final String STUCK_BEHIND_IT = "stuck-behind-the-restamped-one";
  private static final Duration MAXIMUM_MESSAGE_AGE = Duration.ofMillis(500);
  private static final long LONGER_THAN_THE_MAXIMUM_MESSAGE_AGE_MS = 900;
  private static final long WELL_WITHIN_THE_MAXIMUM_MESSAGE_AGE_MS = 150;
  private static final String STILL_ARRIVING = "parts-still-trickling-in";
  private static final int PARTS_OF_THE_SLOW_MESSAGE = 5;
  private static final String DISCARDED_FOR_REDOWNLOAD = "message-discarded-for-redownload";
  private static final String PENDING_IN_ANOTHER_CYCLE = "message-pending-in-another-cycle";

  private final KnownUuidsContainer knownMessageUuids = new KnownUuidsContainer(new Object());
  private final List<String> abandonedUuids = new ArrayList<>();

  private final PartialMessageAssembler assembler =
      new PartialMessageAssembler(
          LoggerFactory.getLogger(PartialMessageAssemblerTest.class),
          () -> knownMessageUuids,
          abandonedUuids::add,
          Duration.ofMinutes(5));

  @Nested
  @DisplayName("Assembling a message whose parts and metadata arrive concurrently")
  class ConcurrentArrivals {

    @Test
    @DisplayName(
        "A part being stored while the metadata replaces the message under assembly is kept")
    void metadataArrivingWhileAPartIsStored_doesNotLoseThatPart() throws Exception {
      CountDownLatch partIsAboutToBeStored = new CountDownLatch(1);
      CountDownLatch metadataHasBeenHandled = new CountDownLatch(1);
      assembler.receiveMetadata(
          UUID_UNDER_ASSEMBLY,
          new MessagePausingBeforeStoringAPart(partIsAboutToBeStored, metadataHasBeenHandled));

      Thread partArrival =
          new Thread(() -> assembler.receivePart(firstPartOf(UUID_UNDER_ASSEMBLY)), "part-arrival");
      partArrival.start();
      assertThat(partIsAboutToBeStored.await(10, TimeUnit.SECONDS))
          .as("the arriving part should have reached the point where it stores itself")
          .isTrue();

      assembler.receiveMetadata(UUID_UNDER_ASSEMBLY, PartialTracingMessage.builder().build());
      metadataHasBeenHandled.countDown();
      partArrival.join(TimeUnit.SECONDS.toMillis(10));

      assertThat(assembler.snapshot().get(UUID_UNDER_ASSEMBLY))
          .as(
              "%s announced %s parts, so it is still under assembly",
              UUID_UNDER_ASSEMBLY, ANNOUNCED_PARTS)
          .isNotNull()
          .extracting(PartialTracingMessage::getFilledMessageParts)
          .as("the part must have ended up in the message that is actually under assembly")
          .isEqualTo(1);
    }
  }

  @Nested
  @DisplayName("Giving up on messages whose remaining parts stopped arriving")
  class ExpiredMessages {

    @Test
    @DisplayName("A message that expired behind a newer one is still given up on")
    void expiredMessageBehindANewerOne_isStillGivenUpOn() throws Exception {
      assembler.setMaximumMessageAge(MAXIMUM_MESSAGE_AGE);
      assembler.receivePart(firstPartOf(FIRST_TO_ARRIVE));
      assembler.receivePart(firstPartOf(STUCK_BEHIND_IT));
      Thread.sleep(LONGER_THAN_THE_MAXIMUM_MESSAGE_AGE_MS);
      assembler.receiveMetadata(FIRST_TO_ARRIVE, PartialTracingMessage.builder().build());

      assembler.removeExpiredMessages();

      assertThat(assembler.snapshot()).doesNotContainKey(STUCK_BEHIND_IT);
      assertThat(abandonedUuids).contains(STUCK_BEHIND_IT);
      assertThat(knownMessageUuids.contains(STUCK_BEHIND_IT))
          .as("the uuid reservation must be released so a catch-up download can re-fetch it")
          .isFalse();
    }

    @Test
    @DisplayName("A message whose parts keep arriving is only given up on once they stop")
    void messageStillReceivingParts_isOnlyGivenUpOnOnceThePartsStop() throws Exception {
      assembler.setMaximumMessageAge(MAXIMUM_MESSAGE_AGE);
      assembler.receivePart(partOf(STILL_ARRIVING, 0, PARTS_OF_THE_SLOW_MESSAGE));

      for (int index = 1; index < PARTS_OF_THE_SLOW_MESSAGE; index++) {
        Thread.sleep(WELL_WITHIN_THE_MAXIMUM_MESSAGE_AGE_MS);
        assembler.receivePart(partOf(STILL_ARRIVING, index, PARTS_OF_THE_SLOW_MESSAGE));
        assembler.removeExpiredMessages();
      }
      assertThat(abandonedUuids)
          .as(
              "%s took longer than %s in total, but never stalled for that long",
              STILL_ARRIVING, MAXIMUM_MESSAGE_AGE)
          .isEmpty();

      Thread.sleep(LONGER_THAN_THE_MAXIMUM_MESSAGE_AGE_MS);
      assembler.removeExpiredMessages();

      assertThat(abandonedUuids).containsExactly(STILL_ARRIVING);
    }
  }

  @Nested
  @DisplayName("Redownloading messages discarded as incomplete")
  class RedownloadedMessages {

    @Test
    @DisplayName("A part arriving while its uuid is pending redownload is rejected")
    void partArrivingWhileItsUuidIsPendingRedownload_isRejected() {
      assembler.receivePart(firstPartOf(DISCARDED_FOR_REDOWNLOAD));
      assembler.discardIncompleteMessagesForRedownload();

      assembler.receivePart(firstPartOf(DISCARDED_FOR_REDOWNLOAD));

      assertThat(assembler.snapshot()).doesNotContainKey(DISCARDED_FOR_REDOWNLOAD);
      assertThat(knownMessageUuids.contains(DISCARDED_FOR_REDOWNLOAD))
          .as("a stray live arrival must not re-claim a uuid a redownload is about to fetch")
          .isFalse();
    }

    @Test
    @DisplayName("Once the redownload finishes, the uuid can be assembled again")
    void afterRedownloadFinishes_theUuidCanBeAssembledAgain() {
      assembler.receivePart(firstPartOf(DISCARDED_FOR_REDOWNLOAD));
      var discardedUuids = assembler.discardIncompleteMessagesForRedownload();
      assembler.finishRedownload(discardedUuids);

      assembler.receivePart(firstPartOf(DISCARDED_FOR_REDOWNLOAD));

      assertThat(assembler.snapshot()).containsKey(DISCARDED_FOR_REDOWNLOAD);
    }

    @Test
    @DisplayName("Finishing one redownload does not release a uuid pending in another")
    void finishingOneRedownload_doesNotReleaseAUuidPendingInAnotherOverlappingOne() {
      assembler.receivePart(firstPartOf(DISCARDED_FOR_REDOWNLOAD));
      var firstCycle = assembler.discardIncompleteMessagesForRedownload();

      assembler.receivePart(firstPartOf(PENDING_IN_ANOTHER_CYCLE));
      assembler.discardIncompleteMessagesForRedownload();

      assembler.finishRedownload(firstCycle);
      assembler.receivePart(firstPartOf(PENDING_IN_ANOTHER_CYCLE));

      assertThat(assembler.snapshot())
          .as("a second, still-running redownload cycle must keep its own uuid guarded")
          .doesNotContainKey(PENDING_IN_ANOTHER_CYCLE);
    }
  }

  private TracingMessagePart firstPartOf(String uuid) {
    return partOf(uuid, 0, ANNOUNCED_PARTS);
  }

  private TracingMessagePart partOf(String uuid, int index, int numberOfParts) {
    return TracingMessagePart.builder()
        .uuid(uuid)
        .index(index)
        .numberOfMessages(numberOfParts)
        .data(new byte[] {1, 2, 3})
        .build();
  }

  private static class MessagePausingBeforeStoringAPart extends PartialTracingMessage {

    private final transient CountDownLatch aboutToStore;
    private final transient CountDownLatch mayStore;

    MessagePausingBeforeStoringAPart(CountDownLatch aboutToStore, CountDownLatch mayStore) {
      super(null, null, null, null, Map.of(), 0, 0);
      this.aboutToStore = aboutToStore;
      this.mayStore = mayStore;
    }

    @Override
    public void addMessagePart(TracingMessagePart part) {
      aboutToStore.countDown();
      try {
        mayStore.await(STOP_WAITING_FOR_METADATA_AFTER_MS, TimeUnit.MILLISECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      super.addMessagePart(part);
    }
  }
}
