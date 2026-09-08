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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.sun.net.httpserver.HttpServer;
import de.gematik.rbellogger.util.RbelInternetAddress;
import de.gematik.test.tiger.common.data.config.tigerproxy.DirectReverseProxyInfo;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import de.gematik.test.tiger.config.ResetTigerConfiguration;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** See ADR 025, "Mechanics worth knowing before touching this", before changing this setup. */
@Slf4j
@ResetTigerConfiguration
class TestMovedHostIsFollowed extends AbstractTigerProxyTest {

  private static final String MOVING_HOST = "moved-host.invalid";
  private static final byte[] FIRST_LOCATION = {127, 0, 0, 1};
  private static final byte[] SECOND_LOCATION = {127, 0, 0, 2};

  private HttpServer firstBackend;
  private HttpServer secondBackend;

  @AfterEach
  void tearDown() {
    RbelInternetAddress.resetHostnameResolver();
    if (firstBackend != null) {
      firstBackend.stop(0);
    }
    if (secondBackend != null) {
      secondBackend.stop(0);
    }
  }

  @Test
  void requestsShouldFollowTheHostToItsNewAddressAndThenStayThere() throws Exception {
    startProxyInFrontOfTheMovingHost();

    assertThat(whoAnswered())
        .as("before the move, requests reach the backend the host resolves to")
        .isEqualTo("first");

    resolveMovingHostTo(SECOND_LOCATION);

    assertThat(whoAnswered())
        .as(
            "the host has moved, so the next request has to reach the new backend - while the"
                + " resolved address was captured once and kept for the life of the JVM, this kept"
                + " landing on the first")
        .isEqualTo("second");

    assertThat(whoAnswered())
        .as(
            "and it has to settle there: while the connect address and the pool's reroute check"
                + " read different caches, every request evicted the connection it had just opened")
        .isEqualTo("second");
    assertThat(whoAnswered()).isEqualTo("second");
  }

  @Test
  void aClientThatKeepsItsConnectionOpenShouldStayOnTheBackendItReached() throws Exception {
    startProxyInFrontOfTheMovingHost();
    val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    assertThat(whoAnsweredOn(client))
        .as("before the move, the tunnel is opened to where the host resolves")
        .isEqualTo("first");

    resolveMovingHostTo(SECOND_LOCATION);

    assertThat(whoAnsweredOn(client))
        .as("the tunnel this client is riding was opened to the first backend and stays there")
        .isEqualTo("first");
    assertThat(whoAnsweredOn(client)).isEqualTo("first");

    assertThat(whoAnswered())
        .as("a new client connection opens a new tunnel, and that one follows the move")
        .isEqualTo("second");
  }

  private void startProxyInFrontOfTheMovingHost() throws Exception {
    val sharedPort = startBothBackends();
    resolveMovingHostTo(FIRST_LOCATION);
    spawnTigerProxyWith(
        TigerProxyConfiguration.builder()
            .directReverseProxy(
                DirectReverseProxyInfo.builder().hostname(MOVING_HOST).port(sharedPort).build())
            .build());
  }

  /** A fresh client per request, so each one arrives on its own connection. */
  private String whoAnswered() throws Exception {
    return whoAnsweredOn(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build());
  }

  private String whoAnsweredOn(HttpClient client) throws Exception {
    val request =
        HttpRequest.newBuilder()
            .uri(URI.create("http://localhost:" + tigerProxy.getProxyPort() + "/whoami"))
            .timeout(Duration.ofSeconds(5))
            .GET()
            .build();
    return client.send(request, BodyHandlers.ofString()).body().trim();
  }

  private void resolveMovingHostTo(byte[] location) throws Exception {
    val address = InetAddress.getByAddress(MOVING_HOST, location);
    RbelInternetAddress.setHostnameResolver(
        host -> MOVING_HOST.equals(host) ? address : InetAddress.getByName(host));
  }

  private int startBothBackends() throws IOException {
    val sharedPort = freePortOnFirstLocation();
    assumeTrue(canBind(SECOND_LOCATION, sharedPort), "127.0.0.2 is not bindable on this machine");
    firstBackend = backendAt(FIRST_LOCATION, sharedPort, "first");
    secondBackend = backendAt(SECOND_LOCATION, sharedPort, "second");
    return sharedPort;
  }

  private int freePortOnFirstLocation() throws IOException {
    try (val probe = new ServerSocket()) {
      probe.bind(new InetSocketAddress(InetAddress.getByAddress(FIRST_LOCATION), 0));
      return probe.getLocalPort();
    }
  }

  private boolean canBind(byte[] location, int port) {
    try (val probe = new ServerSocket()) {
      probe.bind(new InetSocketAddress(InetAddress.getByAddress(location), port));
      return true;
    } catch (IOException e) {
      return false;
    }
  }

  private HttpServer backendAt(byte[] location, int port, String name) throws IOException {
    val server =
        HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(location), port), 0);
    server.createContext(
        "/whoami",
        exchange -> {
          val body = name.getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, body.length);
          try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
          }
        });
    server.start();
    log.info("backend '{}' listening on {}:{}", name, InetAddress.getByAddress(location), port);
    return server;
  }
}
