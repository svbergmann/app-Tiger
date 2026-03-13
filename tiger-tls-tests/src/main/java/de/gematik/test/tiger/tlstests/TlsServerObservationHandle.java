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
package de.gematik.test.tiger.tlstests;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Represents one running one-shot TLS observation server instance.
 */
public final class TlsServerObservationHandle implements AutoCloseable {

  private final String bindHost;
  private final int port;
  private final Duration timeout;
  private final CompletableFuture<TlsServerObservationReport> observationFuture;
  private final AutoCloseable closeAction;

  /**
   * Creates a handle for one running observation server instance.
   *
   * @param bindHost local bind host of the observation server
   * @param port local port of the observation server
   * @param timeout timeout used when awaiting the observation result
   * @param observationFuture future completed with the observation result
   * @param closeAction callback used to shut down the observation server
   */
  TlsServerObservationHandle(
      String bindHost,
      int port,
      Duration timeout,
      CompletableFuture<TlsServerObservationReport> observationFuture,
      AutoCloseable closeAction) {
    if (bindHost == null || bindHost.isBlank()) {
      throw new IllegalArgumentException("bindHost must not be blank");
    }
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("port must be between 1 and 65535");
    }
    if (timeout == null || timeout.isZero() || timeout.isNegative()) {
      throw new IllegalArgumentException("timeout must be greater than zero");
    }
    if (observationFuture == null) {
      throw new IllegalArgumentException("observationFuture must not be null");
    }
    if (closeAction == null) {
      throw new IllegalArgumentException("closeAction must not be null");
    }
    this.bindHost = bindHost;
    this.port = port;
    this.timeout = timeout;
    this.observationFuture = observationFuture;
    this.closeAction = closeAction;
  }

  /**
   * Returns the local bind host of the observation server.
   *
   * @return local bind host of the observation server
   */
  public String bindHost() {
    return bindHost;
  }

  /**
   * Returns the local TCP port of the observation server.
   *
   * @return local TCP port of the observation server
   */
  public int port() {
    return port;
  }

  /**
   * Waits for the one-shot observation result.
   *
   * @return completed server-side TLS observation report
   * @throws Exception if the observation fails or times out
   */
  public TlsServerObservationReport awaitReport() throws Exception {
    return observationFuture.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
  }

  /**
   * Returns whether the observation result is already available.
   *
   * @return {@code true} if the observation result is already available
   */
  public boolean completed() {
    return observationFuture.isDone();
  }

  /**
   * Closes the running observation server.
   *
   * @throws Exception if the observation server cannot be closed cleanly
   */
  @Override
  public void close() throws Exception {
    closeAction.close();
  }
}
