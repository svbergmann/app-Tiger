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

/**
 * Identifies the server endpoint that should be tested.
 *
 * @param host TCP host name or IP address
 * @param port TCP port
 * @param sniHostName optional SNI host name used during the handshake
 */
public record TlsTestTarget(String host, int port, String sniHostName) {

  /**
   * Creates a TLS target and defaults the SNI host name to the target host.
   *
   * @param host TCP host name or IP address
   * @param port TCP port
   */
  public TlsTestTarget(String host, int port) {
    this(host, port, host);
  }

  /**
   * Creates a validated TLS target.
   *
   * @param host TCP host name or IP address
   * @param port TCP port
   * @param sniHostName optional SNI host name used during the handshake
   */
  public TlsTestTarget {
    if (host == null || host.isBlank()) {
      throw new IllegalArgumentException("host must not be blank");
    }
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("port must be between 1 and 65535");
    }
    sniHostName = sniHostName == null || sniHostName.isBlank() ? host : sniHostName;
  }

  /**
   * Returns the host name that should be used for SNI.
   *
   * @return the explicit SNI host or the target host
   */
  public String effectiveSniHostName() {
    return sniHostName;
  }
}
