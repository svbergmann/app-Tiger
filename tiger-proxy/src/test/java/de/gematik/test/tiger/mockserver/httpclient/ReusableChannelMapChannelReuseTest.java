/*
 *  Copyright 2021-2026 gematik GmbH
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
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */
package de.gematik.test.tiger.mockserver.httpclient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import de.gematik.test.tiger.mockserver.httpclient.ReusableChannelMap.ChannelId;
import de.gematik.test.tiger.mockserver.model.HttpRequest;
import de.gematik.test.tiger.mockserver.model.SocketAddress;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Regression test for TGR-1930: channel reuse broken because ChannelId lookup used
 * getRemoteServerAddress() while channel registration used retrieveActualRemoteAddress(). When
 * remoteServerAddress is null but is resolvable via outgoingChannel, lookups always missed, forcing
 * a new TCP connection on every request.
 */
class ReusableChannelMapChannelReuseTest {

  @Test
  void channelShouldBeReusedWhenRemoteAddressIsResolvedViaOutgoingChannel() {
    var remoteAddress = new InetSocketAddress("localhost", 8080);
    var incomingChannel = mockChannel();

    // Simulate the outgoingChannel providing the remote address (remoteServerAddress is null)
    var outgoingChannel = mockChannel();
    when(outgoingChannel.remoteAddress()).thenReturn(remoteAddress);

    // First request: remoteServerAddress is set explicitly (as in channel creation path)
    var firstRequest = new HttpRequestInfo(incomingChannel, null, remoteAddress);

    var channelFuture = mock(ChannelFuture.class);
    var completedChannel = mockCompletedChannel();
    when(channelFuture.channel()).thenReturn(completedChannel);

    var channelMap = new ReusableChannelMap();
    channelMap.addChannel(ChannelId.from(firstRequest), channelFuture);

    // Second request: remoteServerAddress is null, but outgoingChannel has the address.
    // This is the scenario that broke channel reuse before the fix.
    var secondRequest =
        HttpRequestInfo.builder()
            .incomingChannel(incomingChannel)
            .remoteServerAddress(null)
            .outgoingChannel(outgoingChannel)
            .build();

    var reusedChannel = channelMap.getChannelToReuse(secondRequest);

    assertThat(reusedChannel)
        .as("Channel should be reused when remote address is resolved via outgoingChannel.")
        .isNotNull();
  }

  @Test
  void channelShouldNotBeReusedByADifferentIncomingChannel() {
    var remoteAddress = new InetSocketAddress("localhost", 8080);

    var firstClient = mockChannel();
    var channelFuture = mock(ChannelFuture.class);
    var completedChannel = mockCompletedChannel();
    when(channelFuture.channel()).thenReturn(completedChannel);

    var channelMap = new ReusableChannelMap();
    channelMap.addChannel(
        ChannelId.from(new HttpRequestInfo(firstClient, null, remoteAddress)), channelFuture);

    var secondClient = mockChannel();
    var otherClientsRequest = new HttpRequestInfo(secondClient, null, remoteAddress);

    assertThat(channelMap.getChannelToReuse(otherClientsRequest))
        .as(
            "A backend connection opened for one downstream client must never be handed to another"
                + " - the backend scopes connection-bound authentication (NTLM, Negotiate) to the"
                + " socket, and Authorization is forwarded verbatim.")
        .isNull();
  }

  @Test
  void reuseShouldStillWorkForFurtherRequestsOfTheSameIncomingChannel() {
    var remoteAddress = new InetSocketAddress("localhost", 8080);
    var client = mockChannel();

    var channelFuture = mock(ChannelFuture.class);
    var completedChannel = mockCompletedChannel();
    when(channelFuture.channel()).thenReturn(completedChannel);

    var channelMap = new ReusableChannelMap();
    channelMap.addChannel(
        ChannelId.from(new HttpRequestInfo(client, null, remoteAddress)), channelFuture);

    assertThat(channelMap.getChannelToReuse(new HttpRequestInfo(client, null, remoteAddress)))
        .as("Follow-up requests on the same client connection must still reuse the backend channel")
        .isNotNull();
  }

  @Test
  void channelShouldNotBeReusedForDifferentHostnameBehindSameIp() {
    // Two vhosts resolving to the same IP:port — a typical ingress/discovery-document scenario.
    var remoteAddress = new InetSocketAddress("10.0.0.1", 443);
    var client = mockChannel();

    var channelFuture = mock(ChannelFuture.class);
    var completedChannel = mockCompletedChannel();
    when(channelFuture.channel()).thenReturn(completedChannel);

    var requestForHostA =
        new HttpRequestInfo(
            client,
            new HttpRequest()
                .setReceiverAddress(
                    new SocketAddress()
                        .withHost("vhost-a.example.com")
                        .withPort(443)
                        .withScheme(SocketAddress.Scheme.HTTPS)),
            remoteAddress);

    var channelMap = new ReusableChannelMap();
    channelMap.addChannel(ChannelId.from(requestForHostA), channelFuture);

    var requestForHostB =
        new HttpRequestInfo(
            client,
            new HttpRequest()
                .setReceiverAddress(
                    new SocketAddress()
                        .withHost("vhost-b.example.com")
                        .withPort(443)
                        .withScheme(SocketAddress.Scheme.HTTPS)),
            remoteAddress);

    assertThat(channelMap.getChannelToReuse(requestForHostB))
        .as(
            "A connection opened for vhost-a must not be handed to a request for vhost-b, "
                + "even if both resolve to the same IP:port.")
        .isNull();
  }

  /**
   * The regression guard for the pool key itself. If the resolved IP were part of {@link
   * ChannelId}, a host that starts resolving elsewhere would hash into a different bucket - the
   * channels still pointing at the old address would never be looked at again, so the reroute
   * handling below could never fire. Keys built for the same host must stay equal no matter where
   * it currently resolves.
   */
  @Test
  void keyMustIgnoreResolvedIpSoARerouteStaysInTheSameBucket() {
    var client = mockChannel();

    var beforeReroute = ChannelId.from(requestFor(client, "idp.example.com", "10.0.0.1"));
    var afterReroute = ChannelId.from(requestFor(client, "idp.example.com", "10.0.0.2"));

    assertThat(afterReroute)
        .as(
            "The pool key describes where the request was headed, not where the socket landed -"
                + " otherwise a rerouted host lands in a different bucket and its stale channels"
                + " are never evicted.")
        .isEqualTo(beforeReroute);
    assertThat(afterReroute.hashCode()).isEqualTo(beforeReroute.hashCode());
  }

  @Test
  void pooledChannelPointingAtAnOldAddressShouldBeEvictedAfterAReroute() {
    var client = mockChannel();
    // "localhost" resolves to 127.0.0.1 from the hosts file - no network, no flakiness.
    var pooled = channelConnectedTo("10.0.0.1", 443);

    var channelMap = new ReusableChannelMap();
    channelMap.addChannel(ChannelId.from(requestFor(client, "localhost", "10.0.0.1")), pooled);

    assertThat(channelMap.getChannelToReuse(requestFor(client, "localhost", "127.0.0.1")))
        .as(
            "The socket still points at 10.0.0.1 while the host now resolves to 127.0.0.1, so the"
                + " channel must not be handed out to talk to the old server.")
        .isNull();

    // Without this the test would also pass with the resolved IP back in the key, where the lookup
    // misses an empty bucket and the stale channel is simply left behind.
    verify(pooled.channel()).close();
  }

  @Test
  void pooledChannelShouldStillBeReusedWhenTheAddressIsUnchanged() {
    var client = mockChannel();
    var pooled = channelConnectedTo("127.0.0.1", 443);

    var channelMap = new ReusableChannelMap();
    channelMap.addChannel(ChannelId.from(requestFor(client, "localhost", "127.0.0.1")), pooled);

    assertThat(channelMap.getChannelToReuse(requestFor(client, "localhost", "127.0.0.1")))
        .as("A channel whose socket still matches where the host resolves must be reused")
        .isNotNull();
  }

  @Test
  void hostShouldBeMatchedCaseInsensitively() {
    var client = mockChannel();

    assertThat(ChannelId.from(requestFor(client, "IDP.Example.COM", "10.0.0.1")))
        .as("host names are case-insensitive (RFC 4343), so one host must not occupy two buckets")
        .isEqualTo(ChannelId.from(requestFor(client, "idp.example.com", "10.0.0.1")));
  }

  @Test
  void poolShouldNotGrowBeyondMaxChannelsPerKey() {
    var client = mockChannel();
    var channelMap = new ReusableChannelMap();
    channelMap.setMaxChannelsPerKey(3);
    var channelId = ChannelId.from(requestFor(client, "idp.example.com", "10.0.0.1"));

    var added = new ArrayList<ChannelFuture>();
    for (int i = 0; i < 10; i++) {
      var channelFuture = channelConnectedTo("10.0.0.1", 443);
      added.add(channelFuture);
      channelMap.addChannel(channelId, channelFuture);
    }

    assertThat(channelMap.getEntries())
        .as(
            "the TTL sweep is the only other reclamation path, so the bucket has to be bounded here")
        .hasSize(3);
  }

  @Test
  void evictionShouldCloseTheChannelsItDrops() {
    var client = mockChannel();
    var channelMap = new ReusableChannelMap();
    channelMap.setMaxChannelsPerKey(1);
    var channelId = ChannelId.from(requestFor(client, "idp.example.com", "10.0.0.1"));

    var evicted = channelConnectedTo("10.0.0.1", 443);
    channelMap.addChannel(channelId, evicted);
    channelMap.addChannel(channelId, channelConnectedTo("10.0.0.1", 443));

    verify(evicted.channel()).close();
  }

  @Test
  void inFlightChannelsShouldSurviveTheBoundRatherThanBeAborted() {
    var client = mockChannel();
    var channelMap = new ReusableChannelMap();
    channelMap.setMaxChannelsPerKey(1);
    var channelId = ChannelId.from(requestFor(client, "idp.example.com", "10.0.0.1"));

    var inFlight = channelWithOutstandingResponse();
    channelMap.addChannel(channelId, inFlight);
    channelMap.addChannel(channelId, channelConnectedTo("10.0.0.1", 443));

    verify(inFlight.channel(), never()).close();
  }

  /**
   * The pool's only exit for a dead channel. Closing a channel does not remove it from the pool
   * (see {@code ClientBootstrapFactory.registerNewChannel}), and a dead channel is never handed
   * out, so it can never fail in use and be removed that way either. If the sweep skips it, it
   * stays forever - and since the key carries the incoming channel, that is one permanent entry per
   * client connection.
   */
  @Test
  void deadChannelsShouldBeReclaimedBySweepEvenBeforeTheyExpire() {
    var client = mockChannel();
    var channelMap = new ReusableChannelMap();
    channelMap.setChannelPoolTtlMillis(TimeUnit.HOURS.toMillis(1));
    var channelId = ChannelId.from(requestFor(client, "idp.example.com", "10.0.0.1"));

    var dead = deadChannel();
    channelMap.addChannel(channelId, dead);

    channelMap.cleanupExpiredChannels();

    assertThat(channelMap.getEntries()).isEmpty();
  }

  @Test
  void sweepShouldNotTouchAHealthyChannelInsideItsTtl() {
    var client = mockChannel();
    var channelMap = new ReusableChannelMap();
    channelMap.setChannelPoolTtlMillis(TimeUnit.HOURS.toMillis(1));
    var channelId = ChannelId.from(requestFor(client, "idp.example.com", "10.0.0.1"));
    var healthy = channelConnectedTo("10.0.0.1", 443);
    channelMap.addChannel(channelId, healthy);

    channelMap.cleanupExpiredChannels();

    assertThat(channelMap.getEntries()).hasSize(1);
    verify(healthy.channel(), never()).close();
  }

  @Test
  void sweepShouldNotAbortAnInFlightRequestHoweverLongItHasBeenPooled() {
    var client = mockChannel();
    var channelMap = new ReusableChannelMap();
    channelMap.setChannelPoolTtlMillis(0);
    var channelId = ChannelId.from(requestFor(client, "idp.example.com", "10.0.0.1"));
    var inFlight = channelWithOutstandingResponse();
    channelMap.addChannel(channelId, inFlight);

    channelMap.cleanupExpiredChannels();

    verify(inFlight.channel(), never()).close();
  }

  /**
   * A client connection can hold more than one backend channel - two destinations land in two
   * buckets, and concurrent requests to one destination open extra channels because an in-flight
   * one cannot be reused. The {@code OUTGOING_CHANNEL} attribute is single-valued and overwritten
   * each time, so closing it on disconnect reaches only the last; every earlier one was left open
   * and unreachable until the TTL sweep got to it.
   */
  @Test
  void closingAClientConnectionShouldCloseEveryBackendChannelItOpened() {
    var client = mockChannel();
    var channelMap = new ReusableChannelMap();
    var toFirstBackend = channelConnectedTo("10.0.0.1", 443);
    var toSecondBackend = channelConnectedTo("10.0.0.2", 443);
    channelMap.addChannel(
        ChannelId.from(requestFor(client, "a.example.com", "10.0.0.1")), toFirstBackend);
    channelMap.addChannel(
        ChannelId.from(requestFor(client, "b.example.com", "10.0.0.2")), toSecondBackend);

    channelMap.removeAllFor(client);

    verify(toFirstBackend.channel()).close();
    verify(toSecondBackend.channel()).close();
    assertThat(channelMap.getEntries()).isEmpty();
  }

  @Test
  void closingOneClientConnectionShouldLeaveAnotherClientsChannelsAlone() {
    var leaving = mockChannel();
    var staying = mockChannel();
    var channelMap = new ReusableChannelMap();
    var leavingChannel = channelConnectedTo("10.0.0.1", 443);
    var stayingChannel = channelConnectedTo("10.0.0.1", 443);
    channelMap.addChannel(
        ChannelId.from(requestFor(leaving, "a.example.com", "10.0.0.1")), leavingChannel);
    channelMap.addChannel(
        ChannelId.from(requestFor(staying, "a.example.com", "10.0.0.1")), stayingChannel);

    channelMap.removeAllFor(leaving);

    verify(leavingChannel.channel()).close();
    verify(stayingChannel.channel(), never()).close();
    assertThat(channelMap.getEntries()).hasSize(1);
  }

  /**
   * With a forward proxy configured, netty's {@code ProxyHandler} connects the socket to the proxy
   * and tunnels onwards, so the socket's peer is the proxy and never the target. Judging staleness
   * by the socket's own remote address would therefore find a mismatch for every single pooled
   * channel and close the whole pool on every lookup - pooling would be off entirely whenever a
   * forward proxy is in use.
   */
  @Test
  void aChannelTunnelledThroughAForwardProxyShouldNotCountAsRerouted() {
    var client = mockChannel();
    // headed for 127.0.0.1, where "localhost" still resolves, but sitting on the proxy's socket
    var pooled = channelTargeting("127.0.0.1", 443, "192.168.99.1");

    var channelMap = new ReusableChannelMap();
    channelMap.addChannel(ChannelId.from(requestFor(client, "localhost", "127.0.0.1")), pooled);

    assertThat(channelMap.getChannelToReuse(requestFor(client, "localhost", "127.0.0.1")))
        .as("The target has not moved, so the tunnel through the proxy is still good.")
        .isNotNull();
    verify(pooled.channel(), never()).close();
  }

  /**
   * A dead channel counts as evictable when the bound is hit - it used to be filtered out, so the
   * bound closed a healthy channel and kept the corpse.
   *
   * <p>Eviction is oldest-first among everything that has no request in flight, so which of the two
   * goes here follows from the insertion order rather than from any dead-before-healthy preference.
   * In practice the two coincide: the bucket is kept oldest-first by re-inserting on handout, and a
   * dead channel is never handed out, so it drifts to the front on its own.
   */
  @Test
  void theBoundShouldBeWillingToEvictADeadChannel() {
    var client = mockChannel();
    var channelMap = new ReusableChannelMap();
    channelMap.setMaxChannelsPerKey(1);
    var channelId = ChannelId.from(requestFor(client, "idp.example.com", "10.0.0.1"));

    var dead = deadChannel();
    channelMap.addChannel(channelId, dead);
    var healthy = channelConnectedTo("10.0.0.1", 443);
    channelMap.addChannel(channelId, healthy);

    verify(dead.channel()).close();
    verify(healthy.channel(), never()).close();
  }

  /** A channel whose socket has gone away: done connecting, no longer active. */
  private ChannelFuture deadChannel() {
    var channel = mockChannelWithPerKeyAttributes();
    when(channel.isActive()).thenReturn(false);
    when(channel.remoteAddress()).thenReturn(new InetSocketAddress("10.0.0.1", 443));

    var channelFuture = mock(ChannelFuture.class);
    when(channelFuture.channel()).thenReturn(channel);
    when(channelFuture.isDone()).thenReturn(true);
    return channelFuture;
  }

  /** A channel mid-exchange: the response is still outstanding, so it must not be reclaimed. */
  private ChannelFuture channelWithOutstandingResponse() {
    var channel = mockChannelWithPerKeyAttributes();
    when(channel.remoteAddress()).thenReturn(new InetSocketAddress("10.0.0.1", 443));
    setAttribute(channel, NettyHttpClient.ERROR_IF_CHANNEL_CLOSED_WITHOUT_RESPONSE, Boolean.TRUE);
    setAttribute(channel, NettyHttpClient.RESPONSE_FUTURE, new CompletableFuture<>());

    var channelFuture = mock(ChannelFuture.class);
    when(channelFuture.channel()).thenReturn(channel);
    when(channelFuture.isDone()).thenReturn(true);
    return channelFuture;
  }

  /**
   * {@link #mockChannel()} hands the same Attribute back for every key, which is fine until a test
   * needs two attributes to differ - stubbing one would then answer for all of them.
   */
  @SuppressWarnings("unchecked")
  private Channel mockChannelWithPerKeyAttributes() {
    var channel = mock(Channel.class);
    var attributes = new HashMap<AttributeKey<?>, Attribute<Object>>();
    when(channel.attr(any()))
        .thenAnswer(
            invocation ->
                attributes.computeIfAbsent(
                    invocation.getArgument(0), key -> mock(Attribute.class)));
    when(channel.id()).thenReturn(mock(io.netty.channel.ChannelId.class));
    when(channel.isActive()).thenReturn(true);
    return channel;
  }

  @SuppressWarnings("unchecked")
  private static <T> void setAttribute(Channel channel, AttributeKey<T> key, T value) {
    when(((Attribute<T>) channel.attr(key)).get()).thenReturn(value);
  }

  private static HttpRequestInfo requestFor(Channel client, String host, String resolvesTo) {
    return new HttpRequestInfo(
        client,
        new HttpRequest()
            .setReceiverAddress(
                new SocketAddress()
                    .withHost(host)
                    .withPort(443)
                    .withScheme(SocketAddress.Scheme.HTTPS)),
        new InetSocketAddress(resolvesTo, 443));
  }

  /** A pooled channel opened towards {@code ip:port}, with the socket landing there as well. */
  private ChannelFuture channelConnectedTo(String ip, int port) {
    return channelTargeting(ip, port, ip);
  }

  /**
   * A pooled channel headed for {@code targetIp} whose socket actually sits on {@code socketPeerIp}
   * - the same thing for a direct connection, different once a forward proxy is in the way.
   */
  private ChannelFuture channelTargeting(String targetIp, int port, String socketPeerIp) {
    var connected = mockChannelWithPerKeyAttributes();
    setAttribute(connected, NettyHttpClient.REMOTE_SOCKET, new InetSocketAddress(targetIp, port));
    when(connected.remoteAddress()).thenReturn(new InetSocketAddress(socketPeerIp, port));
    var channelFuture = mock(ChannelFuture.class);
    when(channelFuture.channel()).thenReturn(connected);
    return channelFuture;
  }

  @SuppressWarnings("unchecked")
  private Channel mockChannel() {
    var channel = mock(Channel.class);
    var attr = (Attribute<Object>) mock(Attribute.class);
    when(channel.attr(any())).thenReturn(attr);
    when(attr.get()).thenReturn(null);
    // Mock the channel ID for proper equality in ChannelId
    var channelId = mock(io.netty.channel.ChannelId.class);
    when(channel.id()).thenReturn(channelId);
    when(channel.isActive()).thenReturn(true);
    return channel;
  }

  private Channel mockCompletedChannel() {
    // RESPONSE_FUTURE is null → IS_RESPONSE_DONE returns TRUE → canBeReused() = true
    return mockChannel();
  }
}
