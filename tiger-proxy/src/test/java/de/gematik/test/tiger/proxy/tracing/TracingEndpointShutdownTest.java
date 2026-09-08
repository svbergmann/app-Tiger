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
package de.gematik.test.tiger.proxy.tracing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import de.gematik.test.tiger.config.ResetTigerConfiguration;
import de.gematik.test.tiger.proxy.TigerProxyApplication;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.messaging.converter.MappingJackson2MessageConverter;
import org.springframework.messaging.simp.stomp.StompHeaders;
import org.springframework.messaging.simp.stomp.StompSessionHandlerAdapter;
import org.springframework.web.socket.WebSocketHttpHeaders;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.messaging.WebSocketStompClient;
import org.springframework.web.socket.sockjs.client.SockJsClient;
import org.springframework.web.socket.sockjs.client.WebSocketTransport;

/**
 * A test run only ends once the JVM has no non-daemon threads left, so closing the tracing
 * endpoint's spring context must leave none of its thread pools running. The pools are created
 * lazily by SockJS - a session has to be opened first, otherwise no scheduler thread ever exists
 * and this test would pass without proving anything.
 */
@Slf4j
@ResetTigerConfiguration
class TracingEndpointShutdownTest {

  private static final String SCHEDULER_THREAD_PREFIX = "TGR_scheduler-";

  @Test
  void closingContext_shouldTerminateTracingSchedulerThreads() throws Exception {
    final Set<Thread> preexisting = schedulerThreads();
    // an own context, not @SpringBootTest: the test has to close it itself, which the spring test
    // framework would otherwise do only after the test has already finished asserting
    final ConfigurableApplicationContext applicationContext =
        new SpringApplicationBuilder(TigerProxyApplication.class)
            .web(WebApplicationType.SERVLET)
            .properties("server.port=0")
            .run();
    try {
      openSockJsSession(
          ((WebServerApplicationContext) applicationContext).getWebServer().getPort());
      assertThat(schedulerThreadsBeyond(preexisting))
          .as("SockJS session must have started the tracing scheduler pool")
          .isNotEmpty();
    } finally {
      applicationContext.close();
    }

    await()
        .atMost(Duration.ofSeconds(30))
        .untilAsserted(() -> assertThat(schedulerThreadsBeyond(preexisting)).isEmpty());
  }

  private void openSockJsSession(int port) throws Exception {
    var stompClient =
        new WebSocketStompClient(
            new SockJsClient(List.of(new WebSocketTransport(new StandardWebSocketClient()))));
    stompClient.setMessageConverter(new MappingJackson2MessageConverter());
    var session =
        stompClient
            .connectAsync(
                "http://localhost:" + port + "/tracing",
                new WebSocketHttpHeaders(),
                new StompHeaders(),
                new StompSessionHandlerAdapter() {})
            .get(5, TimeUnit.SECONDS);
    try {
      assertThat(session.isConnected()).isTrue();
    } finally {
      session.disconnect();
      stompClient.stop();
    }
  }

  private static Set<Thread> schedulerThreadsBeyond(Set<Thread> known) {
    return schedulerThreads().stream()
        .filter(thread -> !known.contains(thread))
        .collect(Collectors.toSet());
  }

  private static Set<Thread> schedulerThreads() {
    return Thread.getAllStackTraces().keySet().stream()
        .filter(thread -> thread.getName().startsWith(SCHEDULER_THREAD_PREFIX))
        .filter(Thread::isAlive)
        .collect(Collectors.toSet());
  }
}
