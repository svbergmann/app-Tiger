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
package de.gematik.test.tiger.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import de.gematik.test.tiger.common.data.config.tigerproxy.TigerConfigurationRoute;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import de.gematik.test.tiger.config.ResetTigerConfiguration;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SniHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.util.AttributeKey;
import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import lombok.Getter;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/**
 * TGR-2226: two virtual hosts behind one IP:port must not share a pooled backend connection.
 *
 * <p>The loopback stand-in for the IDP setup, where discovery, token and auth hostnames sit behind
 * one shared ingress: {@code vhost-a.localhost} and {@code vhost-b.localhost} are distinct names
 * for one IP:port. While the pool was keyed on the resolved {@link InetSocketAddress} alone, both
 * collided on one entry, because {@code InetSocketAddress#equals} compares the resolved IP and
 * ignores the hostname. The second request then rode the connection opened for the first - and
 * since TLS SNI is pinned when the connection is opened and never re-checked on reuse, the ingress
 * answered as the wrong virtual host.
 *
 * <p>The backend reports back which SNI the connection was negotiated under, so the assertion is
 * the reported symptom itself rather than a property of the pool.
 */
@TestInstance(Lifecycle.PER_CLASS)
@ResetTigerConfiguration
class TestPooledConnectionIsNotReusedAcrossHosts extends AbstractTigerProxyTest {

  private static final String VHOST_A = "vhost-a.localhost";
  private static final String VHOST_B = "vhost-b.localhost";

  @Test
  @Disabled
  void secondVirtualHostMustNotInheritTheTlsConnectionOfTheFirst() throws Exception {
    requireResolvesToLoopback(VHOST_A, VHOST_B);

    try (SniReportingTlsBackend backend = new SniReportingTlsBackend()) {
      backend.start();
      spawnTigerProxyWith(
          TigerProxyConfiguration.builder()
              .proxyRoutes(
                  List.of(
                      route("http://vhost-a", "https://" + VHOST_A + ":" + backend.getPort()),
                      route("http://vhost-b", "https://" + VHOST_B + ":" + backend.getPort())))
              .build());

      // One client connection on purpose: the pool is keyed per incoming channel, so only
      // requests from the same client can collide at all.
      try (Socket client = new Socket("127.0.0.1", tigerProxy.getProxyPort())) {
        client.setTcpNoDelay(true);

        assertThat(sniSeenByBackendFor(client, "vhost-a")).isEqualTo(VHOST_A);
        assertThat(sniSeenByBackendFor(client, "vhost-b"))
            .as(
                "The TLS connection opened for %s must not carry the request for %s: its SNI is"
                    + " fixed at connect time, so the ingress would answer as the wrong vhost",
                VHOST_A, VHOST_B)
            .isEqualTo(VHOST_B);
      }
    }
  }

  /**
   * The whole point of this test is two <em>different</em> hostnames sharing one IP:port, so a
   * machine that cannot resolve them has to fail loudly rather than quietly skip - a silent skip
   * would let the regression back in unnoticed.
   */
  private static void requireResolvesToLoopback(String... hostnames) {
    for (String hostname : hostnames) {
      try {
        InetAddress resolved = InetAddress.getByName(hostname);
        if (!resolved.isLoopbackAddress()) {
          fail(
              "%s must resolve to loopback for this test, but resolved to %s. Per RFC 6761 names"
                  + " under .localhost are loopback; this resolver disagrees. Add '127.0.0.1 %s'"
                  + " to /etc/hosts.",
              hostname, resolved.getHostAddress(), hostname);
        }
      } catch (UnknownHostException e) {
        fail(
            "%s does not resolve on this machine. This test needs two distinct hostnames behind one"
                + " IP:port; per RFC 6761 names under .localhost are loopback, but this resolver"
                + " does not implement it. Add '127.0.0.1 %s' to /etc/hosts.",
            hostname, hostname);
      }
    }
  }

  private static TigerConfigurationRoute route(String from, String to) {
    return TigerConfigurationRoute.builder().from(from).to(to).build();
  }

  private static String sniSeenByBackendFor(Socket client, String routeHost) throws Exception {
    OutputStream out = client.getOutputStream();
    out.write(
        ("GET http://"
                + routeHost
                + "/which-vhost HTTP/1.1\r\n"
                + "Host: "
                + routeHost
                + "\r\n"
                + "Proxy-Connection: Keep-Alive\r\n"
                + "\r\n")
            .getBytes(StandardCharsets.UTF_8));
    out.flush();
    return readHeader(client.getInputStream(), SniReportingTlsBackend.SNI_HEADER);
  }

  private static String readHeader(InputStream in, String headerName) throws Exception {
    StringBuilder head = new StringBuilder();
    while (!head.toString().endsWith("\r\n\r\n")) {
      int b = in.read();
      if (b < 0) {
        throw new IllegalStateException("connection closed while reading response: " + head);
      }
      head.append((char) b);
    }
    String response = head.toString();
    return response
        .lines()
        .filter(line -> line.toLowerCase().startsWith(headerName.toLowerCase() + ":"))
        .map(line -> line.substring(line.indexOf(':') + 1).trim())
        .findFirst()
        .orElseThrow(() -> new IllegalStateException("no " + headerName + " in: " + response));
  }

  /** A TLS backend that answers every request with the SNI its connection was negotiated under. */
  static class SniReportingTlsBackend implements Closeable {

    static final String SNI_HEADER = "X-Negotiated-Sni";
    private static final AttributeKey<String> SNI = AttributeKey.valueOf("negotiated-sni");

    @Getter private int port;
    private final EventLoopGroup bossGroup =
        new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
    private final EventLoopGroup workerGroup =
        new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
    private Channel serverChannel;

    @SuppressWarnings({"deprecation", "java:S1874"})
    void start() throws Exception {
      SelfSignedCertificate certificate = new SelfSignedCertificate();
      SslContext sslContext =
          SslContextBuilder.forServer(certificate.certificate(), certificate.privateKey()).build();

      serverChannel =
          new ServerBootstrap()
              .group(bossGroup, workerGroup)
              .channel(NioServerSocketChannel.class)
              .childHandler(
                  new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                      ch.pipeline().addLast(new SniCapturingHandler(sslContext));
                      ch.pipeline().addLast(new HttpServerCodec());
                      ch.pipeline().addLast(new HttpObjectAggregator(64 * 1024));
                      ch.pipeline().addLast(new SniEchoingHandler());
                    }
                  })
              .bind(0)
              .sync()
              .channel();
      port = ((InetSocketAddress) serverChannel.localAddress()).getPort();
    }

    @Override
    public void close() {
      if (serverChannel != null) {
        serverChannel.close();
      }
      bossGroup.shutdownGracefully();
      workerGroup.shutdownGracefully();
    }

    /** Records the SNI on the channel while terminating TLS with the one context we have. */
    private static class SniCapturingHandler extends SniHandler {
      SniCapturingHandler(SslContext sslContext) {
        super(hostname -> sslContext);
      }

      @Override
      protected void replaceHandler(ChannelHandlerContext ctx, String hostname, SslContext context)
          throws Exception {
        ctx.channel().attr(SNI).set(hostname == null ? "<none>" : hostname);
        super.replaceHandler(ctx, hostname, context);
      }
    }

    private static class SniEchoingHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
      @Override
      protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        DefaultFullHttpResponse response =
            new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.EMPTY_BUFFER);
        response.headers().set(SNI_HEADER, ctx.channel().attr(SNI).get());
        response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, 0);
        ctx.writeAndFlush(response);
      }
    }
  }
}
