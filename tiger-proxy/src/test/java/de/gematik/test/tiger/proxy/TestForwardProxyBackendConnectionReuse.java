/*
 *  Copyright 2021-2025 gematik GmbH
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
package de.gematik.test.tiger.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.test.tiger.common.data.config.tigerproxy.TigerConfigurationRoute;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import de.gematik.test.tiger.config.ResetTigerConfiguration;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
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
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/**
 * Diagnostic for TGR-2201: mimics the TI-M setup (plain-HTTP forward-proxy request routed to an
 * HTTPS backend on loopback) and counts how many TCP connections the proxy opens towards the
 * backend for N sequential requests.
 *
 * <p>Expected (4.2.5 behaviour): one backend connection per incoming client connection.
 */
@Slf4j
@TestInstance(Lifecycle.PER_CLASS)
@ResetTigerConfiguration
class TestForwardProxyBackendConnectionReuse extends AbstractTigerProxyTest {

  private static final int REQUESTS = 20;

  @Test
  void singleKeepAliveClientConnection_shouldReuseOneBackendConnection() throws Exception {
    try (CountingTlsBackend backend = new CountingTlsBackend()) {
      backend.start();
      spawnTigerProxyWith(
          TigerProxyConfiguration.builder()
              .proxyRoutes(
                  List.of(
                      TigerConfigurationRoute.builder()
                          .from("http://tim-backend")
                          .to("https://127.0.0.1:" + backend.getPort())
                          .build()))
              .build());

      List<Long> timings = new ArrayList<>();
      try (Socket client = new Socket("127.0.0.1", tigerProxy.getProxyPort())) {
        client.setTcpNoDelay(true);
        OutputStream out = client.getOutputStream();
        InputStream in = client.getInputStream();
        for (int i = 0; i < REQUESTS; i++) {
          long start = System.nanoTime();
          out.write(
              ("GET http://tim-backend/req"
                      + i
                      + " HTTP/1.1\r\n"
                      + "Host: tim-backend\r\n"
                      + "Proxy-Connection: Keep-Alive\r\n"
                      + "User-Agent: repro\r\n"
                      + "\r\n")
                  .getBytes(StandardCharsets.UTF_8));
          out.flush();
          readOneHttpResponse(in);
          timings.add((System.nanoTime() - start) / 1_000_000);
        }
      }

      report("SINGLE keep-alive client connection", timings, backend);

      assertThat(backend.connectionsAccepted.get())
          .as("Requests on one keep-alive client connection must share one backend connection")
          .isLessThanOrEqualTo(2);
    }
  }

  @Test
  void newClientConnectionPerRequest_shouldNotShareBackendConnections() throws Exception {
    try (CountingTlsBackend backend = new CountingTlsBackend()) {
      backend.start();
      spawnTigerProxyWith(
          TigerProxyConfiguration.builder()
              .proxyRoutes(
                  List.of(
                      TigerConfigurationRoute.builder()
                          .from("http://tim-backend")
                          .to("https://127.0.0.1:" + backend.getPort())
                          .build()))
              .build());

      List<Long> timings = new ArrayList<>();
      for (int i = 0; i < REQUESTS; i++) {
        long start = System.nanoTime();
        try (Socket client = new Socket("127.0.0.1", tigerProxy.getProxyPort())) {
          client.setTcpNoDelay(true);
          OutputStream out = client.getOutputStream();
          InputStream in = client.getInputStream();
          out.write(
              ("GET http://tim-backend/req"
                      + i
                      + " HTTP/1.1\r\n"
                      + "Host: tim-backend\r\n"
                      + "Proxy-Connection: Keep-Alive\r\n"
                      + "User-Agent: repro\r\n"
                      + "\r\n")
                  .getBytes(StandardCharsets.UTF_8));
          out.flush();
          readOneHttpResponse(in);
        }
        timings.add((System.nanoTime() - start) / 1_000_000);
      }

      report("NEW client connection per request", timings, backend);

      assertThat(backend.connectionsAccepted.get())
          .as(
              "Each downstream client connection must get its own backend connection. Pooled"
                  + " channels are keyed by the incoming channel, so a connection opened for one"
                  + " client is never handed to the next - otherwise the backend, which scopes"
                  + " connection-bound authentication (NTLM, Negotiate) to the socket, would treat"
                  + " the second client as the first.")
          .isGreaterThanOrEqualTo(REQUESTS);
    }
  }

  private void report(String label, List<Long> timings, CountingTlsBackend backend)
      throws InterruptedException {
    Thread.sleep(500);
    List<Long> sorted = timings.stream().sorted().toList();
    log.info(
        "\n==== TGR-2201 REPRO: {} ====\n"
            + "  requests sent to proxy   : {}\n"
            + "  backend TCP connections  : {}\n"
            + "  backend requests received: {}\n"
            + "  first request            : {} ms\n"
            + "  median                   : {} ms\n"
            + "  max                      : {} ms\n"
            + "  all                      : {}\n"
            + "===============================================",
        label,
        timings.size(),
        backend.connectionsAccepted.get(),
        backend.requestsReceived.get(),
        timings.get(0),
        sorted.get(sorted.size() / 2),
        sorted.get(sorted.size() - 1),
        timings);
  }

  private static void readOneHttpResponse(InputStream in) throws Exception {
    StringBuilder headers = new StringBuilder();
    int consecutive = 0;
    while (consecutive < 2) {
      int b = in.read();
      if (b < 0) {
        throw new IllegalStateException("connection closed while reading headers: " + headers);
      }
      headers.append((char) b);
      if (b == '\n') {
        consecutive++;
      } else if (b != '\r') {
        consecutive = 0;
      }
    }
    int contentLength = 0;
    boolean chunked = false;
    for (String line : headers.toString().split("\r\n")) {
      String lower = line.toLowerCase();
      if (lower.startsWith("content-length:")) {
        contentLength = Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
      } else if (lower.startsWith("transfer-encoding:") && lower.contains("chunked")) {
        chunked = true;
      }
    }
    if (chunked) {
      // read until terminating 0-length chunk
      String tail = "";
      while (!tail.endsWith("0\r\n\r\n")) {
        int b = in.read();
        if (b < 0) {
          return;
        }
        tail = (tail + (char) b);
        if (tail.length() > 8) {
          tail = tail.substring(tail.length() - 8);
        }
      }
    } else {
      in.readNBytes(contentLength);
    }
  }

  /** TLS backend that keeps connections alive and counts accepted TCP connections. */
  static class CountingTlsBackend implements Closeable {
    @Getter private int port;
    final AtomicInteger connectionsAccepted = new AtomicInteger();
    final AtomicInteger requestsReceived = new AtomicInteger();
    private final EventLoopGroup bossGroup =
        new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
    private final EventLoopGroup workerGroup =
        new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
    private Channel serverChannel;

    @SuppressWarnings({"deprecation", "java:S1874"})
    void start() throws Exception {
      SelfSignedCertificate ssc = new SelfSignedCertificate();
      SslContext sslCtx =
          SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey())
              .protocols("TLSv1.2", "TLSv1.3")
              .build();
      ServerBootstrap b = new ServerBootstrap();
      b.group(bossGroup, workerGroup)
          .channel(NioServerSocketChannel.class)
          .childHandler(
              new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                  connectionsAccepted.incrementAndGet();
                  log.info(
                      "BACKEND: accepted TCP connection #{} from {}",
                      connectionsAccepted.get(),
                      ch.remoteAddress());
                  ch.pipeline()
                      .addLast(
                          new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelInactive(ChannelHandlerContext ctx) {
                              log.info(
                                  "BACKEND: connection closed {}", ctx.channel().remoteAddress());
                              ctx.fireChannelInactive();
                            }
                          });
                  ch.pipeline().addLast(sslCtx.newHandler(ch.alloc()));
                  ch.pipeline().addLast(new HttpServerCodec());
                  ch.pipeline().addLast(new HttpObjectAggregator(1024 * 1024));
                  ch.pipeline()
                      .addLast(
                          new SimpleChannelInboundHandler<FullHttpRequest>() {
                            @Override
                            protected void channelRead0(
                                ChannelHandlerContext ctx, FullHttpRequest request) {
                              requestsReceived.incrementAndGet();
                              byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
                              DefaultFullHttpResponse response =
                                  new DefaultFullHttpResponse(
                                      HttpVersion.HTTP_1_1,
                                      HttpResponseStatus.OK,
                                      Unpooled.wrappedBuffer(body));
                              response
                                  .headers()
                                  .set(HttpHeaderNames.CONTENT_TYPE, "application/json");
                              response
                                  .headers()
                                  .setInt(HttpHeaderNames.CONTENT_LENGTH, body.length);
                              response.headers().set(HttpHeaderNames.CONNECTION, "keep-alive");
                              ctx.writeAndFlush(response);
                            }
                          });
                }
              });
      serverChannel = b.bind(0).sync().channel();
      port = ((InetSocketAddress) serverChannel.localAddress()).getPort();
      log.info("BACKEND: listening on https://127.0.0.1:{}", port);
    }

    @Override
    public void close() {
      if (serverChannel != null) {
        serverChannel.close();
      }
      bossGroup.shutdownGracefully();
      workerGroup.shutdownGracefully();
    }
  }
}
