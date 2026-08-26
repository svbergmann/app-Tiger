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
package de.gematik.test.tiger.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import de.gematik.rbellogger.util.GlobalServerMap;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerConfigurationRoute;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import de.gematik.test.tiger.config.ResetTigerConfiguration;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/**
 * Guards the RBEL parsing throughput of the proxy (TGR-2201).
 *
 * <p>Forwarding a message is only half the job - the test suites wait for the parsed RBEL messages,
 * so parse throughput is what decides the wall-clock time of a run. This drives traffic the way the
 * TI-M test driver does, with a new client connection per request, and checks that the parser keeps
 * up instead of building an ever growing backlog.
 *
 * <p>The regression this guards against made per-message conversion scale with the number of
 * connections the run had already produced: catching up on 800 messages went from ~0.25s to ~15s.
 */
@Slf4j
@TestInstance(Lifecycle.PER_CLASS)
@ResetTigerConfiguration
class TestRbelParsingThroughput extends AbstractTigerProxyTest {

  private static final int WARMUP_REQUESTS = 10;
  private static final int BULK_REQUESTS = 400;

  private long registeredProcessId;

  /**
   * GlobalServerMap is process-wide state, so anything this test registers would otherwise stay
   * visible to every later test in the same surefire fork.
   */
  @AfterEach
  void removeBundledServerRegistration() {
    GlobalServerMap.getProcessIdToBundledServerName().remove(registeredProcessId);
    GlobalServerMap.getPortToProcessId().values().removeIf(pid -> pid == registeredProcessId);
  }

  @Test
  void parsingShouldKeepUpWithTrafficFromManyShortLivedConnections() throws Exception {
    // A registered bundled server makes the port-to-process resolution actually run for every
    // message, which is the situation in a real tiger test suite with managed servers. Without it
    // the resolution short-circuits and this test would not exercise the expensive path at all.
    registeredProcessId = ProcessHandle.current().pid();
    GlobalServerMap.updateGlobalServerMap(fakeBackendServerPort, registeredProcessId, "backend");

    spawnTigerProxyWith(
        TigerProxyConfiguration.builder()
            .proxyRoutes(
                List.of(
                    TigerConfigurationRoute.builder()
                        .from("http://tim-backend")
                        .to("http://localhost:" + fakeBackendServerPort)
                        .build()))
            .build());

    for (int i = 0; i < WARMUP_REQUESTS; i++) {
      sendOneRequest();
    }

    // a burst, so the parser has to keep up while traffic is flowing
    for (int i = 0; i < BULK_REQUESTS; i++) {
      sendOneRequest();
    }
    final int expectedMessages = (WARMUP_REQUESTS + BULK_REQUESTS) * 2;
    long catchupStart = System.currentTimeMillis();
    await()
        .atMost(Duration.ofSeconds(120))
        .pollInterval(Duration.ofMillis(50))
        .until(() -> tigerProxy.getRbelMessagesList().size() >= expectedMessages);
    long catchupMs = System.currentTimeMillis() - catchupStart;

    log.info(
        "\n==== RBEL PARSING THROUGHPUT ====\n"
            + "  burst   : {} requests, catch-up after last request {} ms\n"
            + "  messages: {}\n"
            + "=================================",
        BULK_REQUESTS,
        catchupMs,
        tigerProxy.getRbelMessagesList().size());

    assertThat(catchupMs)
        .as(
            "After the traffic stops the parser must drain its backlog quickly. If this blows up,"
                + " per-message conversion has started to scale with the size of the run - see"
                + " TGR-2201, where an uncached OS connection-table lookup per message made this"
                + " ~15s instead of ~0.25s.")
        .isLessThan(5_000L);
  }

  private void sendOneRequest() throws Exception {
    // a new connection per request, as the TI-M test driver does
    try (Socket client = new Socket("127.0.0.1", tigerProxy.getProxyPort())) {
      client.setTcpNoDelay(true);
      OutputStream out = client.getOutputStream();
      InputStream in = client.getInputStream();
      out.write(
          ("GET http://tim-backend/foobar HTTP/1.1\r\n"
                  + "Host: tim-backend\r\n"
                  + "Proxy-Connection: Keep-Alive\r\n"
                  + "\r\n")
              .getBytes(StandardCharsets.UTF_8));
      out.flush();
      readOneHttpResponse(in);
    }
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
      String tail = "";
      while (!tail.endsWith("0\r\n\r\n")) {
        int b = in.read();
        if (b < 0) {
          return;
        }
        tail = tail + (char) b;
        if (tail.length() > 8) {
          tail = tail.substring(tail.length() - 8);
        }
      }
    } else {
      in.readNBytes(contentLength);
    }
  }
}
