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

import static de.gematik.rbellogger.util.MemoryConstants.MB;

import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketTransportRegistration;

@Configuration
@EnableWebSocketMessageBroker
@RequiredArgsConstructor
@Slf4j
public class TracingEndpointConfiguration
    implements WebSocketMessageBrokerConfigurer, DisposableBean {

  private final TigerProxyConfiguration tigerProxyConfiguration;
  private final List<ThreadPoolTaskExecutor> taskExecutors = new ArrayList<>();
  private final List<ThreadPoolTaskScheduler> schedulers = new ArrayList<>();

  // Only a core pool size, no maximum: the default queue capacity is unbounded, so the pool never
  // grows beyond its core size and a maximum would just read as if it meant something.
  private ThreadPoolTaskExecutor createAndRegisterTaskExecutor(int poolSize) {
    final ThreadPoolTaskExecutor threadPoolTaskExecutor = new ThreadPoolTaskExecutor();
    threadPoolTaskExecutor.setWaitForTasksToCompleteOnShutdown(true);
    threadPoolTaskExecutor.setAwaitTerminationSeconds(2);
    threadPoolTaskExecutor.setCorePoolSize(poolSize);
    threadPoolTaskExecutor.initialize();
    taskExecutors.add(threadPoolTaskExecutor);
    return threadPoolTaskExecutor;
  }

  private ThreadPoolTaskScheduler createAndRegisterTaskScheduler() {
    var scheduler = new ThreadPoolTaskScheduler();
    scheduler.setThreadNamePrefix("TGR_scheduler-");
    scheduler.setWaitForTasksToCompleteOnShutdown(true);
    scheduler.setAwaitTerminationSeconds(2);
    scheduler.setPoolSize(4);
    scheduler.initialize();
    schedulers.add(scheduler);
    return scheduler;
  }

  @Override
  public void configureMessageBroker(MessageBrokerRegistry config) {
    config
        .enableSimpleBroker("/topic")
        .setHeartbeatValue(heartbeatIntervalsInMillis())
        .setTaskScheduler(createAndRegisterTaskScheduler());
    config.setApplicationDestinationPrefixes(
        tigerProxyConfiguration.getTrafficEndpointConfiguration().getStompTopic());
    config.setPreservePublishOrder(true);
  }

  private long[] heartbeatIntervalsInMillis() {
    final long interval =
        Duration.ofSeconds(tigerProxyConfiguration.getStompHeartbeatInSeconds()).toMillis();
    return new long[] {interval, interval};
  }

  @Override
  public void registerStompEndpoints(StompEndpointRegistry registry) {
    // Intentionally register both variants on the same path: SockJS fallback and raw WebSocket
    // STOMP.
    registry
        .addEndpoint(tigerProxyConfiguration.getTrafficEndpointConfiguration().getWsEndpoint())
        .setAllowedOriginPatterns("*")
        .withSockJS()
        .setTaskScheduler(createAndRegisterTaskScheduler());

    registry
        .addEndpoint(tigerProxyConfiguration.getTrafficEndpointConfiguration().getWsEndpoint())
        .setAllowedOriginPatterns("*");

    registry
        .addEndpoint("/newMessages")
        .withSockJS()
        .setTaskScheduler(createAndRegisterTaskScheduler());
  }

  @Override
  public void configureClientOutboundChannel(ChannelRegistration registration) {
    registration.taskExecutor(createAndRegisterTaskExecutor(4));
  }

  @Override
  public void configureClientInboundChannel(ChannelRegistration registration) {
    registration.taskExecutor(createAndRegisterTaskExecutor(4));
  }

  @Override
  public void destroy() {
    taskExecutors.forEach(ThreadPoolTaskExecutor::shutdown);
    schedulers.forEach(ThreadPoolTaskScheduler::shutdown);
  }

  @Override
  public void configureWebSocketTransport(WebSocketTransportRegistration registration) {
    log.info(
        "Configuring WebSocket transport with send buffer size limit: {} MB, send time limit: {}s",
        tigerProxyConfiguration.getStompServerSendBufferSizeInMb(),
        tigerProxyConfiguration.getStompServerSendTimeLimitInSeconds());
    registration.setSendBufferSizeLimit(
        tigerProxyConfiguration.getStompServerSendBufferSizeInMb() * MB);
    registration.setSendTimeLimit(
        tigerProxyConfiguration.getStompServerSendTimeLimitInSeconds() * 1000);
  }
}
