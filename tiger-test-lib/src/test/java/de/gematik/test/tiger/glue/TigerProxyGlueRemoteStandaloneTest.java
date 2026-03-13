/*
 *
 * Copyright 2021-2026 gematik GmbH
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
package de.gematik.test.tiger.glue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.test.tiger.common.config.RbelModificationDescription;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.test.tiger.common.util.TigerSerializationUtil;
import de.gematik.test.tiger.lib.TigerDirector;
import de.gematik.test.tiger.proxy.data.TigerProxyRoute;
import de.gematik.test.tiger.testenvmgr.TigerTestEnvMgr;
import de.gematik.test.tiger.testenvmgr.junit.TigerTest;
import de.gematik.test.tiger.testenvmgr.servers.TigerProxyServer;
import de.gematik.test.tiger.testenvmgr.util.TigerTestEnvException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Integration tests for remote standalone Tiger Proxy manipulation steps.
 */
class TigerProxyGlueRemoteStandaloneTest {

  private final TigerProxyGlue tigerProxyGlue = new TigerProxyGlue();

  /**
   * Verifies that routes and modifications can be created, listed, removed, and cleared on the
   * standalone Tiger Proxy selected by cluster id.
   *
   * @param tigerTestEnvMgr active test environment manager
   */
  @TigerTest(
      tigerYaml =
          """
config_ports:
  alpha:
    admin: ${free.port.0}
    proxy: ${free.port.1}
    serverPort: ${free.port.2}
  beta:
    admin: ${free.port.3}
    proxy: ${free.port.4}
    serverPort: ${free.port.5}
servers:
  alphaHttpbin:
    type: httpbin
    serverPort: ${tiger.config_ports.alpha.serverPort}
    healthcheckUrl: http://localhost:${tiger.config_ports.alpha.serverPort}/status/200
  betaHttpbin:
    type: httpbin
    serverPort: ${tiger.config_ports.beta.serverPort}
    healthcheckUrl: http://localhost:${tiger.config_ports.beta.serverPort}/status/200
  alphaProxy:
    type: tigerProxy
    tigerProxyConfiguration:
      clusterId: alpha
      adminPort: ${tiger.config_ports.alpha.admin}
      proxyPort: ${tiger.config_ports.alpha.proxy}
      directReverseProxy:
        hostname: localhost
        port: ${tiger.config_ports.alpha.serverPort}
  betaProxy:
    type: tigerProxy
    tigerProxyConfiguration:
      clusterId: beta
      adminPort: ${tiger.config_ports.beta.admin}
      proxyPort: ${tiger.config_ports.beta.proxy}
      directReverseProxy:
        hostname: localhost
        port: ${tiger.config_ports.beta.serverPort}
""")
  @Test
  void shouldManipulateRemoteTigerProxyResourcesByClusterId(final TigerTestEnvMgr tigerTestEnvMgr) {
    bindTigerDirector(tigerTestEnvMgr);

    final TigerProxyServer alphaProxy =
        tigerTestEnvMgr.findTigerProxyServerByClusterId("alpha").orElseThrow();
    final TigerProxyServer betaProxy =
        tigerTestEnvMgr.findTigerProxyServerByClusterId("beta").orElseThrow();

    tigerProxyGlue.addTigerProxyResourceOnClusterAndStore(
        TigerProxyResourceType.ROUTE,
        "alpha",
        "alphaRoute",
        """
        {
          "from": "http://alpha.example",
          "to": "http://localhost:${tiger.config_ports.alpha.serverPort}"
        }
        """);

    final TigerProxyRoute createdRoute =
        TigerSerializationUtil.fromJson(
            TigerGlobalConfiguration.readStringOptional("alphaRoute").orElseThrow(),
            TigerProxyRoute.class);
    assertThat(createdRoute.getId()).isNotBlank();
    assertThat(createdRoute.getFrom()).isEqualTo("http://alpha.example");
    assertThat(managedRoutes(alphaProxy))
        .extracting(TigerProxyRoute::getFrom)
        .contains("http://alpha.example");
    assertThat(managedRoutes(betaProxy)).isEmpty();

    tigerProxyGlue.storeTigerProxyResourcesFromCluster(
        TigerProxyResourceType.ROUTE, "alpha", "alphaRoutes");
    assertThat(TigerGlobalConfiguration.readStringOptional("alphaRoutes").orElseThrow())
        .contains("http://alpha.example");

    tigerProxyGlue.removeTigerProxyResourceOnCluster(
        TigerProxyResourceType.ROUTE, createdRoute.getId(), "alpha");
    assertThat(managedRoutes(alphaProxy)).isEmpty();

    tigerProxyGlue.addTigerProxyResourceOnCluster(
        TigerProxyResourceType.ROUTE,
        "alpha",
        """
        {
          "from": "http://alpha.clear.me",
          "to": "http://localhost:${tiger.config_ports.alpha.serverPort}"
        }
        """);
    assertThat(managedRoutes(alphaProxy))
        .extracting(TigerProxyRoute::getFrom)
        .contains("http://alpha.clear.me");

    tigerProxyGlue.clearTigerProxyResourcesOnCluster(TigerProxyResourceType.ROUTE, "alpha");
    assertThat(managedRoutes(alphaProxy)).isEmpty();

    tigerProxyGlue.addTigerProxyResourceOnClusterAndStore(
        TigerProxyResourceType.MODIFICATION,
        "beta",
        "betaModification",
        """
        {
          "name": "beta-modification",
          "condition": "isRequest",
          "targetElement": "$.header.user-agent",
          "replaceWith": "cluster-beta"
        }
        """);

    final RbelModificationDescription createdModification =
        TigerSerializationUtil.fromJson(
            TigerGlobalConfiguration.readStringOptional("betaModification").orElseThrow(),
            RbelModificationDescription.class);
    assertThat(createdModification.getName()).isEqualTo("beta-modification");
    assertThat(betaProxy.getTigerProxy().getModifications())
        .extracting(RbelModificationDescription::getName)
        .contains("beta-modification");
    assertThat(alphaProxy.getTigerProxy().getModifications()).isEmpty();

    tigerProxyGlue.storeTigerProxyResourcesFromCluster(
        TigerProxyResourceType.MODIFICATION, "beta", "betaModifications");
    assertThat(TigerGlobalConfiguration.readStringOptional("betaModifications").orElseThrow())
        .contains("beta-modification");

    tigerProxyGlue.removeTigerProxyResourceOnCluster(
        TigerProxyResourceType.MODIFICATION, "beta-modification", "beta");
    assertThat(betaProxy.getTigerProxy().getModifications()).isEmpty();

    tigerProxyGlue.addTigerProxyResourceOnCluster(
        TigerProxyResourceType.MODIFICATION,
        "beta",
        """
        {
          "name": "beta-clear-me",
          "condition": "isRequest",
          "targetElement": "$.header.user-agent",
          "replaceWith": "cluster-beta"
        }
        """);
    assertThat(betaProxy.getTigerProxy().getModifications())
        .extracting(RbelModificationDescription::getName)
        .contains("beta-clear-me");

    tigerProxyGlue.clearTigerProxyResourcesOnCluster(
        TigerProxyResourceType.MODIFICATION, "beta");
    assertThat(betaProxy.getTigerProxy().getModifications()).isEmpty();
  }

  /**
   * Verifies that remote standalone Tiger Proxy access fails with a dedicated glue exception when
   * the requested cluster id is unknown.
   *
   * @param tigerTestEnvMgr active test environment manager
   */
  @TigerTest(
      tigerYaml =
          """
config_ports:
  alpha:
    admin: ${free.port.0}
    proxy: ${free.port.1}
    serverPort: ${free.port.2}
servers:
  alphaHttpbin:
    type: httpbin
    serverPort: ${tiger.config_ports.alpha.serverPort}
    healthcheckUrl: http://localhost:${tiger.config_ports.alpha.serverPort}/status/200
  alphaProxy:
    type: tigerProxy
    tigerProxyConfiguration:
      clusterId: alpha
      adminPort: ${tiger.config_ports.alpha.admin}
      proxyPort: ${tiger.config_ports.alpha.proxy}
      directReverseProxy:
        hostname: localhost
        port: ${tiger.config_ports.alpha.serverPort}
""")
  @Test
  void shouldFailForUnknownClusterId(final TigerTestEnvMgr tigerTestEnvMgr) {
    bindTigerDirector(tigerTestEnvMgr);

    assertThatThrownBy(
            () ->
                tigerProxyGlue.storeTigerProxyResourcesFromCluster(
                    TigerProxyResourceType.ROUTE, "missing", "routes"))
        .isInstanceOf(TigerProxyGlue.TigerProxyGlueException.class)
        .hasMessageContaining("missing");
  }

  /**
   * Verifies that duplicate cluster ids are rejected to keep remote standalone Tiger Proxy
   * selection unambiguous.
   *
   * @param tigerTestEnvMgr active test environment manager
   */
  @TigerTest(
      tigerYaml =
          """
config_ports:
  first:
    admin: ${free.port.0}
    proxy: ${free.port.1}
    serverPort: ${free.port.2}
  second:
    admin: ${free.port.3}
    proxy: ${free.port.4}
    serverPort: ${free.port.5}
servers:
  firstHttpbin:
    type: httpbin
    serverPort: ${tiger.config_ports.first.serverPort}
    healthcheckUrl: http://localhost:${tiger.config_ports.first.serverPort}/status/200
  secondHttpbin:
    type: httpbin
    serverPort: ${tiger.config_ports.second.serverPort}
    healthcheckUrl: http://localhost:${tiger.config_ports.second.serverPort}/status/200
  firstProxy:
    type: tigerProxy
    tigerProxyConfiguration:
      clusterId: duplicate
      adminPort: ${tiger.config_ports.first.admin}
      proxyPort: ${tiger.config_ports.first.proxy}
      directReverseProxy:
        hostname: localhost
        port: ${tiger.config_ports.first.serverPort}
  secondProxy:
    type: tigerProxy
    tigerProxyConfiguration:
      clusterId: duplicate
      adminPort: ${tiger.config_ports.second.admin}
      proxyPort: ${tiger.config_ports.second.proxy}
      directReverseProxy:
        hostname: localhost
        port: ${tiger.config_ports.second.serverPort}
""")
  @Test
  void shouldFailForDuplicateClusterIds(final TigerTestEnvMgr tigerTestEnvMgr) {
    bindTigerDirector(tigerTestEnvMgr);

    assertThatThrownBy(
            () ->
                tigerProxyGlue.storeTigerProxyResourcesFromCluster(
                    TigerProxyResourceType.ROUTE, "duplicate", "routes"))
        .isInstanceOf(TigerTestEnvException.class)
        .hasMessageContaining("duplicate");
  }

  /**
   * Binds the shared {@link TigerDirector} singleton to the test environment created for this
   * integration test.
   *
   * @param tigerTestEnvMgr active test environment manager
   */
  private static void bindTigerDirector(final TigerTestEnvMgr tigerTestEnvMgr) {
    ReflectionTestUtils.setField(TigerDirector.class, "tigerTestEnvMgr", tigerTestEnvMgr);
    ReflectionTestUtils.setField(TigerDirector.class, "initialized", true);
  }

  /**
   * Returns only routes managed through the remote manipulation API. Standalone proxies configured
   * with {@code directReverseProxy} keep a bootstrap {@code /} route that must stay in place even
   * after clearing all user-managed routes.
   *
   * @param tigerProxyServer standalone Tiger Proxy server under test
   * @return non-internal routes except the bootstrap reverse-proxy route
   */
  private static List<TigerProxyRoute> managedRoutes(final TigerProxyServer tigerProxyServer) {
    return tigerProxyServer.getTigerProxy().getRoutes().stream()
        .filter(route -> !route.isInternalRoute())
        .filter(route -> !"/".equals(route.getFrom()))
        .toList();
  }
}
