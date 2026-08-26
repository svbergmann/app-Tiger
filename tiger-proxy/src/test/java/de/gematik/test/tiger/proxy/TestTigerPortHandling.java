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

import de.gematik.test.tiger.common.data.config.tigerproxy.*;
import de.gematik.test.tiger.config.ResetTigerConfiguration;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import kong.unirest.core.*;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@Slf4j
@TestInstance(Lifecycle.PER_CLASS)
@ResetTigerConfiguration
class TestTigerPortHandling extends AbstractTigerProxyTest {

  /**
   * TGR-2182. A pooled backend connection is keyed by the incoming channel that opened it, so once
   * the client disconnects it can never be handed out again - it has to be closed right away rather
   * than lingering until the pool TTL expires.
   */
  @Test
  void proxyShouldClosePortToServerAsSoonAsClientPortIsClosed() throws InterruptedException {
    try (FakeHttpServer fakeBackend = new FakeHttpServer()) {
      fakeBackend.startAndExpectOneRequestAndClose();

      spawnProxyRoutingTo(fakeBackend.getPort());

      sendHttpGetAndCloseImmediately("localhost", tigerProxy.getProxyPort());

      boolean closedInTime = fakeBackend.awaitConnectionClosed(2, TimeUnit.SECONDS);

      assertThat(closedInTime)
          .withFailMessage(
              "Der Proxy hat die Verbindung zum Backend nicht rechtzeitig geschlossen.")
          .isTrue();
    } catch (IOException e) {
      throw new RuntimeException(e);
    } catch (Exception e) {
      if (Thread.interrupted()) throw new InterruptedException();
    }
  }

  /** The TTL sweep is the backstop for channels whose client connection is alive but idle. */
  @Test
  void unusedBackendConnectionShouldBeClosedByPoolCleanup() throws InterruptedException {
    try (FakeHttpServer fakeBackend = new FakeHttpServer()) {
      fakeBackend.startAndExpectOneRequestAndClose();

      spawnProxyRoutingTo(fakeBackend.getPort());

      sendHttpGetAndCloseImmediately("localhost", tigerProxy.getProxyPort());

      val channelMap =
          tigerProxy
              .getMockServer()
              .getActionHandler()
              .getHttpClient()
              .getClientBootstrapFactory()
              .getChannelMap();
      channelMap.setChannelPoolTtlMillis(0);
      channelMap.cleanupExpiredChannels();

      boolean closedInTime = fakeBackend.awaitConnectionClosed(5, TimeUnit.SECONDS);

      assertThat(closedInTime)
          .withFailMessage("Der Proxy hat die ungenutzte Verbindung zum Backend nicht aufgeräumt.")
          .isTrue();
    } catch (IOException e) {
      throw new RuntimeException(e);
    } catch (Exception e) {
      if (Thread.interrupted()) throw new InterruptedException();
    }
  }

  private void spawnProxyRoutingTo(int backendPort) {
    spawnTigerProxyWith(
        TigerProxyConfiguration.builder()
            .proxyRoutes(
                List.of(
                    TigerConfigurationRoute.builder()
                        .from("/")
                        .to("http://127.0.0.1:" + backendPort)
                        .preserveHostHeader(true)
                        .build()))
            .build());
  }

  class FakeHttpServer implements AutoCloseable {
    private final ServerSocket serverSocket;
    private final CountDownLatch connectionClosedLatch = new CountDownLatch(1);
    private Thread serverThread;

    public FakeHttpServer() throws Exception {
      this.serverSocket = new ServerSocket(0);
    }

    public int getPort() {
      return serverSocket.getLocalPort();
    }

    /**
     * Startet den Server im Hintergrund. Er wartet auf eine Verbindung, liest den Request,
     * antwortet mit HTTP 200 und wartet dann auf den Disconnect.
     */
    public void startAndExpectOneRequestAndClose() {
      serverThread =
          new Thread(
              () -> {
                try (Socket socket = serverSocket.accept();
                    InputStream in = socket.getInputStream();
                    OutputStream out = socket.getOutputStream()) {

                  readHttpRequest(in);
                  send200OkResponse(out);
                  awaitSocketClose(in);

                  connectionClosedLatch.countDown();
                } catch (Exception e) {
                  connectionClosedLatch.countDown();
                }
              });
      serverThread.start();
    }

    /** Blockiert den aufrufenden Thread, bis die Backend-Verbindung geschlossen wurde. */
    public boolean awaitConnectionClosed(long timeout, TimeUnit unit) throws InterruptedException {
      return connectionClosedLatch.await(timeout, unit);
    }

    private void readHttpRequest(InputStream in) throws Exception {
      StringBuilder sb = new StringBuilder();
      int b;
      while ((b = in.read()) != -1) {
        sb.append((char) b);
        if (sb.toString().endsWith("\r\n\r\n")) {
          break; // Header vollständig gelesen
        }
      }
    }

    private void send200OkResponse(OutputStream out) throws Exception {
      String response =
          "HTTP/1.1 200 OK\r\n" + "Content-Length: 2\r\n" + "Connection: keep-alive\r\n\r\n" + "OK";
      out.write(response.getBytes(StandardCharsets.UTF_8));
      out.flush();
    }

    private void awaitSocketClose(InputStream in) throws Exception {
      while (in.read() != -1) {
        // Liest weiter, bis EOF (-1) vom Proxy kommt
      }
    }

    @Override
    public void close() throws Exception {
      if (!serverSocket.isClosed()) {
        serverSocket.close();
      }
      if (serverThread != null) {
        serverThread.interrupt();
      }
    }
  }

  public static void sendHttpGetAndCloseImmediately(String host, int port) throws Exception {
    try (Socket socket = new Socket(host, port);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream()) {

      String request = "GET / HTTP/1.1\r\n" + "Host: " + host + "\r\n\r\n";
      out.write(request.getBytes(StandardCharsets.UTF_8));
      out.flush();

      StringBuilder sb = new StringBuilder();
      int ch;
      while ((ch = in.read()) != -1) {
        sb.append((char) ch);
        if (sb.toString().contains("OK")) {
          break;
        }
      }
    }
  }
}
