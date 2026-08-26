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
package de.gematik.test.tiger.mockserver.httpclient;

import io.netty.channel.ChannelFuture;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * It wraps a ChannelFuture that can be reused if the corresponding response future is already done.
 */
@Getter
@EqualsAndHashCode(exclude = "lastUsedAt")
@RequiredArgsConstructor
@Slf4j
public class ReusableChannel {

  /**
   * The bucket this channel lives in. Carried on the channel so that eviction can hand back plain
   * channels instead of (key, channel) tuples - several channels share one key, so they cannot be
   * collected into a map keyed by it.
   */
  private final ReusableChannelMap.ChannelId channelId;

  private final ChannelFuture futureOutgoingChannel;

  private long lastUsedAt = System.currentTimeMillis();

  /**
   * Whether this channel is free to serve another request. Ownership is not checked here: {@link
   * ReusableChannelMap.ChannelId} already carries the incoming channel, so a pooled channel is only
   * ever offered to the client that opened it.
   *
   * <p>Do not use this to decide whether a channel may be <em>evicted</em>. It is false for two
   * opposite reasons - the channel is dead, or it is busy - and eviction has to tell them apart.
   * Use {@link #isDead()} and {@link #hasRequestInFlight()} for that.
   */
  public boolean canBeReused() {
    return !isDead() && !hasRequestInFlight();
  }

  /**
   * The socket is gone. Nothing will ever hand this channel out again, so it is pure garbage in the
   * pool and may be dropped at any time.
   *
   * <p>Closing the outgoing channel does not remove it from the pool - see the note in {@code
   * ClientBootstrapFactory.registerNewChannel} - so reclaiming these is the sweep's job alone.
   */
  public boolean isDead() {
    return futureOutgoingChannel.isDone() && !futureOutgoingChannel.channel().isActive();
  }

  /**
   * A request is still waiting for its response. Closing such a channel aborts a live exchange, so
   * it is the one state eviction must respect however long the channel has been in the pool -
   * {@code lastUsedAt} only advances on handout, so a slow backend can push it past the TTL.
   */
  public boolean hasRequestInFlight() {
    if (isDead()) {
      return false;
    }
    return SHOULD_I_WAIT_FOR_A_RESPONSE_BEFORE_REUSING.test(futureOutgoingChannel)
        && !IS_RESPONSE_DONE.test(futureOutgoingChannel);
  }

  public void markAsUsed() {
    lastUsedAt = System.currentTimeMillis();
  }

  public boolean isExpired(long ttlMillis) {
    long idleMillis = System.currentTimeMillis() - lastUsedAt;
    return idleMillis > ttlMillis;
  }

  private static final Predicate<ChannelFuture> IS_RESPONSE_DONE =
      f ->
          Optional.ofNullable(f.channel().attr(NettyHttpClient.RESPONSE_FUTURE).get())
              .map(CompletableFuture::isDone)
              .orElse(Boolean.TRUE);

  private static final Predicate<ChannelFuture> SHOULD_I_WAIT_FOR_A_RESPONSE_BEFORE_REUSING =
      f ->
          Optional.ofNullable(
                  f.channel().attr(NettyHttpClient.ERROR_IF_CHANNEL_CLOSED_WITHOUT_RESPONSE).get())
              .orElse(Boolean.FALSE);
}
