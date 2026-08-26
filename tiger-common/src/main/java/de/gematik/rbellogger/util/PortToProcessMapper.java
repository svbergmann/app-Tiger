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
package de.gematik.rbellogger.util;

import static de.gematik.rbellogger.util.GlobalServerMap.mapPortToProcessIds;

import java.util.List;
import java.util.concurrent.ConcurrentMap;
import lombok.extern.slf4j.Slf4j;
import oshi.SystemInfo;
import oshi.software.os.InternetProtocolStats;
import oshi.software.os.OperatingSystem;

@Slf4j
public class PortToProcessMapper {

  private PortToProcessMapper() {
    throw new IllegalStateException("PortToProcessMapper class");
  }

  private static final long CONNECTION_SNAPSHOT_TTL_MILLIS = 1000L;

  private static final SystemInfo SYSTEM_INFO = new SystemInfo();

  @SuppressWarnings("java:S3077")
  private static volatile List<InternetProtocolStats.IPConnection> connectionSnapshot = List.of();

  private static volatile long connectionSnapshotTakenAt = 0L;
  private static long lastMissRefreshAt = 0L;

  public static ConcurrentMap<Integer, Long> getProcessIdsForPort(int port) {
    if (GlobalServerMap.getProcessIdToBundledServerName().isEmpty()) {
      return GlobalServerMap.getPortToProcessId();
    }
    getConnectionsToAndFromPort(port).forEach(PortToProcessMapper::fillMapWithValues);
    return GlobalServerMap.getPortToProcessId();
  }

  private static void fillMapWithValues(InternetProtocolStats.IPConnection connection) {
    if (GlobalServerMap.getProcessIdToBundledServerName()
        .containsKey((long) connection.getowningProcessId())) {
      mapPortToProcessIds(connection.getLocalPort(), connection.getowningProcessId());
      mapPortToProcessIds(connection.getForeignPort(), connection.getowningProcessId());
    }
  }

  public static List<InternetProtocolStats.IPConnection> getConnectionsToAndFromPort(int port) {
    var matches = matchesForPort(currentConnections(), port);
    if (!matches.isEmpty()) {
      return matches;
    }
    if (!shouldRetryAfterMiss()) {
      return List.of();
    }
    return matchesForPort(refreshSnapshot(), port);
  }

  private static synchronized boolean shouldRetryAfterMiss() {
    long now = System.currentTimeMillis();
    if (now - lastMissRefreshAt <= CONNECTION_SNAPSHOT_TTL_MILLIS) {
      return false;
    }
    lastMissRefreshAt = now;
    return true;
  }

  private static List<InternetProtocolStats.IPConnection> matchesForPort(
      List<InternetProtocolStats.IPConnection> connections, int port) {
    return connections.stream()
        .filter(c -> c.getLocalPort() == port || c.getForeignPort() == port)
        .toList();
  }

  private static List<InternetProtocolStats.IPConnection> currentConnections() {
    if (System.currentTimeMillis() - connectionSnapshotTakenAt <= CONNECTION_SNAPSHOT_TTL_MILLIS) {
      return connectionSnapshot;
    }
    return refreshSnapshot();
  }

  private static synchronized List<InternetProtocolStats.IPConnection> refreshSnapshot() {
    OperatingSystem os = SYSTEM_INFO.getOperatingSystem();
    InternetProtocolStats ipStats = os.getInternetProtocolStats();
    connectionSnapshot = ipStats.getConnections();
    connectionSnapshotTakenAt = System.currentTimeMillis();
    return connectionSnapshot;
  }
}
