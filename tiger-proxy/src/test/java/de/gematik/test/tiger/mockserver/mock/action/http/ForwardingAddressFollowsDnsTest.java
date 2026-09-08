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
package de.gematik.test.tiger.mockserver.mock.action.http;

import static de.gematik.test.tiger.mockserver.httpclient.NettyHttpClient.REMOTE_SOCKET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.gematik.rbellogger.util.RbelInternetAddress;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.Attribute;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import lombok.val;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** See ADR 025, "Mechanics worth knowing before touching this", before changing this setup. */
class ForwardingAddressFollowsDnsTest {

  private static final int PORT = 8443;

  @BeforeEach
  @AfterEach
  void restoreRealResolver() {
    RbelInternetAddress.resetHostnameResolver();
  }

  @Test
  void theForwardingAddressShouldFollowTheHostWhenItMoves() throws Exception {
    val oldLocation = InetAddress.getByAddress(new byte[] {10, 0, 0, 1});
    val newLocation = InetAddress.getByAddress(new byte[] {10, 0, 0, 2});
    val ctx = contextTargeting("localhost");

    RbelInternetAddress.setHostnameResolver(host -> oldLocation);
    assertThat(HttpActionHandler.getRemoteAddress(ctx).getAddress()).isEqualTo(oldLocation);

    RbelInternetAddress.setHostnameResolver(host -> newLocation);

    assertThat(HttpActionHandler.getRemoteAddress(ctx).getAddress())
        .as(
            "the host has moved, so the next request has to go to the new address - while the IP"
                + " was captured once and kept forever, the proxy carried on delivering to the old"
                + " server and the pool evicted a channel per request trying to correct it")
        .isEqualTo(newLocation);
  }

  /**
   * Asserts on {@link InetAddress#toString()}, which renders the carried name without ever
   * triggering a lookup: {@code localhost/10.0.0.1} when the name survives, {@code /10.0.0.1} when
   * it was dropped.
   */
  @Test
  void theForwardingAddressShouldCarryTheHostnameSoSniNeedsNoReverseLookup() throws Exception {
    RbelInternetAddress.setHostnameResolver(
        host -> InetAddress.getByAddress(host, new byte[] {10, 0, 0, 1}));

    val forwardTo = HttpActionHandler.getRemoteAddress(contextTargeting("localhost"));

    assertThat(forwardTo.getAddress().toString())
        .as(
            "the name has to survive into the address the connection is made with - without it,"
                + " asking for the SNI server name performs a reverse lookup and sends back"
                + " whatever the PTR record or the local hosts file offers")
        .startsWith("localhost/");
  }

  @Test
  void theForwardingPortShouldBeCarriedThroughUnchanged() throws Exception {
    val someLocation = InetAddress.getByAddress(new byte[] {10, 0, 0, 1});
    RbelInternetAddress.setHostnameResolver(host -> someLocation);

    assertThat(HttpActionHandler.getRemoteAddress(contextTargeting("localhost")).getPort())
        .isEqualTo(PORT);
  }

  /**
   * A context whose channel is addressed to {@code host:PORT}, unresolved so that the loopback
   * short-circuit in {@code getRemoteAddressFromSocket} does not swallow the lookup.
   */
  @SuppressWarnings("unchecked")
  private ChannelHandlerContext contextTargeting(String host) {
    val channel = mock(Channel.class);
    val attribute = (Attribute<InetSocketAddress>) mock(Attribute.class);
    when(attribute.get()).thenReturn(InetSocketAddress.createUnresolved(host, PORT));
    when(channel.attr(REMOTE_SOCKET)).thenReturn(attribute);
    when(channel.localAddress()).thenReturn(null);

    val ctx = mock(ChannelHandlerContext.class);
    when(ctx.channel()).thenReturn(channel);
    return ctx;
  }
}
