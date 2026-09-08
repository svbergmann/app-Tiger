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

import de.gematik.rbellogger.KnownUuidsContainer;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Supplier;
import lombok.Getter;
import lombok.Setter;
import lombok.val;
import org.slf4j.Logger;

/**
 * Collects the metadata frame and the data chunks a traced message is transmitted in, until it is
 * whole. A message under assembly holds a UUID reservation in the converter, so assembly has to be
 * given up on eventually - otherwise a message whose remaining parts never arrive holds that
 * reservation forever.
 */
public class PartialMessageAssembler {

  private final Logger log;
  private final Supplier<KnownUuidsContainer> knownMessageUuids;
  private final Consumer<String> onAssemblyAbandoned;

  @Getter @Setter private Duration maximumMessageAge;

  private final Map<String, PartialTracingMessage> messagesInArrivalOrder = new LinkedHashMap<>();
  private final Set<String> uuidsPendingRedownload = ConcurrentHashMap.newKeySet();

  public PartialMessageAssembler(
      Logger log,
      Supplier<KnownUuidsContainer> knownMessageUuids,
      Consumer<String> onAssemblyAbandoned,
      Duration maximumMessageAge) {
    this.log = log;
    this.knownMessageUuids = knownMessageUuids;
    this.onAssemblyAbandoned = onAssemblyAbandoned;
    this.maximumMessageAge = maximumMessageAge;
  }

  public void receivePart(TracingMessagePart part) {
    final Optional<PartialTracingMessage> wholeMessage;
    synchronized (messagesInArrivalOrder) {
      val assembly =
          startOrContinueAssembly(part.getUuid(), PartialTracingMessage.builder().build());
      if (assembly.isEmpty()) {
        log.atTrace()
            .addArgument(part::getUuid)
            .log("Discarding message part for already-known message {}");
        return;
      }
      val message = assembly.get();
      message.addMessagePart(part);
      wholeMessage = takeIfWhole(message, part.getUuid());
    }
    wholeMessage.ifPresent(this::propagateOutsideMonitor);
  }

  public void receiveMetadata(String uuid, PartialTracingMessage message) {
    final Optional<PartialTracingMessage> wholeMessage;
    synchronized (messagesInArrivalOrder) {
      val partsReceivedSoFar = messagesInArrivalOrder.get(uuid);
      if (partsReceivedSoFar == null && !reserveUuid(uuid)) {
        log.trace("Discarding metadata for already-known message {}", uuid);
        return;
      }
      messagesInArrivalOrder.put(uuid, message);
      if (partsReceivedSoFar != null) {
        message.addMessageParts(partsReceivedSoFar);
      }
      wholeMessage = takeIfWhole(message, uuid);
    }
    wholeMessage.ifPresent(this::propagateOutsideMonitor);
  }

  private Optional<PartialTracingMessage> startOrContinueAssembly(
      String uuid, PartialTracingMessage message) {
    val alreadyBeingAssembled = messagesInArrivalOrder.get(uuid);
    if (alreadyBeingAssembled != null) {
      return Optional.of(alreadyBeingAssembled);
    }
    if (!reserveUuid(uuid)) {
      return Optional.empty();
    }
    messagesInArrivalOrder.put(uuid, message);
    return Optional.of(message);
  }

  private Optional<PartialTracingMessage> takeIfWhole(PartialTracingMessage message, String uuid) {
    if (!message.isComplete()) {
      return Optional.empty();
    }
    messagesInArrivalOrder.remove(uuid);
    return Optional.of(message);
  }

  private void propagateOutsideMonitor(PartialTracingMessage message) {
    message.getMessageFrame().checkForCompletePairAndPropagateIfComplete();
  }

  public void removeExpiredMessages() {
    val abandonedUuids = removeMessagesOlderThan(ZonedDateTime.now().minus(maximumMessageAge));
    abandonedUuids.forEach(this::abandonAssemblyOf);
  }

  private List<String> removeMessagesOlderThan(ZonedDateTime cutoff) {
    val incompleteUuids = new ArrayList<String>();
    synchronized (messagesInArrivalOrder) {
      val entries = messagesInArrivalOrder.entrySet().iterator();
      while (entries.hasNext()) {
        val entry = entries.next();
        val message = entry.getValue();
        if (cutoff.isAfter(message.getLastActivity())) {
          if (!message.isComplete()) {
            incompleteUuids.add(entry.getKey());
          }
          entries.remove();
        }
      }
    }
    return incompleteUuids;
  }

  private void abandonAssemblyOf(String messageUuid) {
    log.atInfo()
        .addArgument(messageUuid)
        .addArgument(maximumMessageAge)
        .log(
            "Giving up on incomplete message {} after {} without a new part, releasing all messages"
                + " queued behind it");
    knownMessageUuids.get().remove(messageUuid);
    onAssemblyAbandoned.accept(messageUuid);
  }

  public Set<String> discardIncompleteMessagesForRedownload() {
    synchronized (messagesInArrivalOrder) {
      val discardedUuids = removeIncompleteMessages();
      discardedUuids.forEach(
          uuid -> {
            log.atDebug()
                .addArgument(uuid)
                .log("Discarding incomplete partial message {} before traffic download");
            uuidsPendingRedownload.add(uuid);
            knownMessageUuids.get().remove(uuid);
          });
      return Set.copyOf(discardedUuids);
    }
  }

  public void finishRedownload(Set<String> discardedUuids) {
    synchronized (messagesInArrivalOrder) {
      uuidsPendingRedownload.removeAll(discardedUuids);
    }
  }

  public boolean isPendingRedownload(String messageUuid) {
    return uuidsPendingRedownload.contains(messageUuid);
  }

  private List<String> removeIncompleteMessages() {
    synchronized (messagesInArrivalOrder) {
      val incompleteUuids =
          messagesInArrivalOrder.entrySet().stream()
              .filter(entry -> !entry.getValue().isComplete())
              .map(Map.Entry::getKey)
              .toList();
      incompleteUuids.forEach(messagesInArrivalOrder::remove);
      return incompleteUuids;
    }
  }

  public Optional<Duration> remainingAssemblyTime(String messageUuid) {
    final PartialTracingMessage message;
    synchronized (messagesInArrivalOrder) {
      message = messagesInArrivalOrder.get(messageUuid);
    }
    return Optional.ofNullable(message)
        .map(partialMessage -> partialMessage.getLastActivity().plus(maximumMessageAge))
        .map(assemblyDeadline -> Duration.between(ZonedDateTime.now(), assemblyDeadline));
  }

  public Map<String, PartialTracingMessage> snapshot() {
    synchronized (messagesInArrivalOrder) {
      return new LinkedHashMap<>(messagesInArrivalOrder);
    }
  }

  public void clear() {
    synchronized (messagesInArrivalOrder) {
      messagesInArrivalOrder.clear();
    }
  }

  private boolean reserveUuid(String uuid) {
    return !uuidsPendingRedownload.contains(uuid) && knownMessageUuids.get().add(uuid);
  }
}
