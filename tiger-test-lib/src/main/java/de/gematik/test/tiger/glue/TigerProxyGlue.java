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

import de.gematik.test.tiger.common.config.RbelModificationDescription;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import de.gematik.test.tiger.common.pki.TigerConfigurationPkiIdentity;
import de.gematik.test.tiger.common.util.TigerSerializationUtil;
import de.gematik.test.tiger.lib.TigerDirector;
import de.gematik.test.tiger.proxy.TigerProxy;
import de.gematik.test.tiger.proxy.client.TigerRemoteProxyClient;
import de.gematik.test.tiger.proxy.data.TigerProxyRoute;
import de.gematik.test.tiger.testenvmgr.servers.TigerProxyServer;
import de.gematik.test.tiger.testenvmgr.util.TigerTestEnvException;
import io.cucumber.java.de.Wenn;
import io.cucumber.java.en.When;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * TGR glue code for manipulating local and remote standalone Tiger Proxy instances.
 */
public class TigerProxyGlue {

  /**
   * Changes the forwardMutualTlsIdentity of the local TigerProxy to the given value. The parameter
   * uses the TigerPkiIdentity-syntax used also for the YAML-configuration. For more information
   * refer to the user manual, section "Configuring PKI identities in Tiger Proxy’s tls section". Be
   * aware: This method reboots the internal mockserver, leading to a short period in which the
   * local TigerProxy can not forward traffic. (It will still function in a mesh-setup, no traffic
   * will be lost). Before the method returns the mockserver is successfully restarted.
   *
   * @param certificateFile The certificate to use. Use TigerPkiIdentity-syntax (e.g.
   *     "my/file/name.p12;p12password")
   */
  @Wenn("TGR ändere die forwardMutualTlsIdentity des lokalen TigerProxies zu {tigerResolvedString}")
  @When("TGR change the local TigerProxy forwardMutualTlsIdentity to {tigerResolvedString}")
  public void setLocalTigerProxyForwardMutualTlsIdentity(final String certificateFile) {
    changeTlsSettingForLocalTigerProxy(
        certificateFile, (cfg, crt) -> cfg.getTls().setForwardMutualTlsIdentity(crt));
  }

  /**
   * Changes the serverIdentity of the local TigerProxy to the given value. The parameter uses the
   * TigerPkiIdentity-syntax used also for the YAML-configuration. For more information refer to the
   * user manual, section "Configuring PKI identities in Tiger Proxy’s tls section". Be aware: This
   * method reboots the internal mockserver, leading to a short period in which the local TigerProxy
   * can not forward traffic. (It will still function in a mesh-setup, no traffic will be lost).
   * Before the method returns the mockserver is successfully restarted.
   *
   * @param certificateFile The certificate to use. Use TigerPkiIdentity-syntax (e.g.
   *     "my/file/name.p12;p12password")
   */
  @Wenn("TGR ändere die serverIdentity des lokalen TigerProxies zu {tigerResolvedString}")
  @When("TGR change the local TigerProxy serverIdentity to {tigerResolvedString}")
  public void setLocalTigerProxyServerIdentity(final String certificateFile) {
    changeTlsSettingForLocalTigerProxy(
        certificateFile, (cfg, crt) -> cfg.getTls().setServerIdentity(crt));
  }

  /**
   * Changes the rootCa of the local TigerProxy to the given value. The parameter uses the
   * TigerPkiIdentity-syntax used also for the YAML-configuration. For more information refer to the
   * user manual, section "Configuring PKI identities in Tiger Proxy’s tls section". Be aware: This
   * method reboots the internal mockserver, leading to a short period in which the local TigerProxy
   * can not forward traffic. (It will still function in a mesh-setup, no traffic will be lost).
   * Before the method returns the mockserver is successfully restarted.
   *
   * @param certificateFile The certificate to use. Use TigerPkiIdentity-syntax (e.g.
   *     "my/file/name.p12;p12password")
   */
  @Wenn("TGR ändere die rootCa des lokalen TigerProxies zu {tigerResolvedString}")
  @When("TGR change the local TigerProxy rootCa to {tigerResolvedString}")
  public void setLocalTigerProxyRootCa(final String certificateFile) {
    changeTlsSettingForLocalTigerProxy(
        certificateFile, (cfg, crt) -> cfg.getTls().setServerRootCa(crt));
  }

  /**
   * Adds a remote Tiger Proxy route or modification on the standalone proxy identified by the
   * given cluster id. The payload must be valid JSON for the selected resource type.
   *
   * @param resourceType Tiger Proxy resource type to create
   * @param clusterId cluster identifier of the remote standalone Tiger Proxy
   * @param jsonPayload JSON payload matching the selected resource type
   */
  @Wenn("TGR füge Tiger Proxy {tigerProxyResourceType} auf Cluster {tigerResolvedString} hinzu:")
  @When("TGR add tiger proxy {tigerProxyResourceType} on cluster {tigerResolvedString}:")
  public void addTigerProxyResourceOnCluster(
      final TigerProxyResourceType resourceType,
      final String clusterId,
      final String jsonPayload) {
    withRemoteTigerProxyClient(
        clusterId, client -> addTigerProxyResource(client, resourceType, jsonPayload));
  }

  /**
   * Adds a remote Tiger Proxy route or modification on the standalone proxy identified by the
   * given cluster id and stores the created resource as JSON in a Tiger variable.
   *
   * @param resourceType Tiger Proxy resource type to create
   * @param clusterId cluster identifier of the remote standalone Tiger Proxy
   * @param variableName Tiger variable receiving the created resource as JSON
   * @param jsonPayload JSON payload matching the selected resource type
   */
  @Wenn(
      "TGR füge Tiger Proxy {tigerProxyResourceType} auf Cluster {tigerResolvedString} hinzu und speichere das Ergebnis in Variable {tigerResolvedString}:")
  @When(
      "TGR add tiger proxy {tigerProxyResourceType} on cluster {tigerResolvedString} and store result in variable {tigerResolvedString}:")
  public void addTigerProxyResourceOnClusterAndStore(
      final TigerProxyResourceType resourceType,
      final String clusterId,
      final String variableName,
      final String jsonPayload) {
    withRemoteTigerProxyClient(
        clusterId,
        client ->
            storeAsJson(
                variableName, addTigerProxyResource(client, resourceType, jsonPayload)));
  }

  /**
   * Removes a remote Tiger Proxy route or modification from the standalone proxy identified by the
   * given cluster id.
   *
   * @param resourceType Tiger Proxy resource type to remove
   * @param resourceIdentifier route id or modification name
   * @param clusterId cluster identifier of the remote standalone Tiger Proxy
   */
  @Wenn(
      "TGR entferne Tiger Proxy {tigerProxyResourceType} {tigerResolvedString} auf Cluster {tigerResolvedString}")
  @When(
      "TGR remove tiger proxy {tigerProxyResourceType} {tigerResolvedString} on cluster {tigerResolvedString}")
  public void removeTigerProxyResourceOnCluster(
      final TigerProxyResourceType resourceType,
      final String resourceIdentifier,
      final String clusterId) {
    withRemoteTigerProxyClient(
        clusterId, client -> removeTigerProxyResource(client, resourceType, resourceIdentifier));
  }

  /**
   * Clears all remote Tiger Proxy resources of the selected type from the standalone proxy
   * identified by the given cluster id.
   *
   * @param resourceType Tiger Proxy resource type to clear
   * @param clusterId cluster identifier of the remote standalone Tiger Proxy
   */
  @Wenn("TGR lösche alle Tiger Proxy {tigerProxyResourceType} auf Cluster {tigerResolvedString}")
  @When("TGR clear tiger proxy {tigerProxyResourceType} on cluster {tigerResolvedString}")
  public void clearTigerProxyResourcesOnCluster(
      final TigerProxyResourceType resourceType, final String clusterId) {
    withRemoteTigerProxyClient(clusterId, client -> clearTigerProxyResources(client, resourceType));
  }

  /**
   * Stores all remote Tiger Proxy resources of the selected type from the standalone proxy
   * identified by the given cluster id as JSON in a Tiger variable.
   *
   * @param resourceType Tiger Proxy resource type to fetch
   * @param clusterId cluster identifier of the remote standalone Tiger Proxy
   * @param variableName Tiger variable receiving the resource list as JSON
   */
  @Wenn(
      "TGR speichere Tiger Proxy {tigerProxyResourceType} von Cluster {tigerResolvedString} in Variable {tigerResolvedString}")
  @When(
      "TGR store tiger proxy {tigerProxyResourceType} from cluster {tigerResolvedString} in variable {tigerResolvedString}")
  public void storeTigerProxyResourcesFromCluster(
      final TigerProxyResourceType resourceType,
      final String clusterId,
      final String variableName) {
    withRemoteTigerProxyClient(
        clusterId, client -> storeAsJson(variableName, getTigerProxyResources(client, resourceType)));
  }

  /**
   * Changes a TLS setting of the local Tiger Proxy and restarts its mock server afterwards.
   *
   * @param certificateFile serialized Tiger PKI identity
   * @param configurationChanger callback changing one TLS field
   */
  private static void changeTlsSettingForLocalTigerProxy(
      final String certificateFile,
      final BiConsumer<TigerProxyConfiguration, TigerConfigurationPkiIdentity>
          configurationChanger) {
    final TigerProxy localTigerProxy =
        TigerDirector.getTigerTestEnvMgr()
            .getLocalTigerProxyOptional()
            .orElseThrow(
                () ->
                    new TigerProxyGlueException(
                        "Could not change settings for the local TigerProxy: The local TigerProxy"
                            + " is inactive"));
    final TigerConfigurationPkiIdentity newIdentity =
        new TigerConfigurationPkiIdentity(certificateFile);
    configurationChanger.accept(localTigerProxy.getTigerProxyConfiguration(), newIdentity);
    localTigerProxy.restartMockserver();
  }

  /**
   * Creates a short-lived REST client for the remote standalone Tiger Proxy identified by the given
   * cluster id, executes the callback, and closes the client afterwards.
   *
   * @param clusterId cluster identifier of the remote standalone Tiger Proxy
   * @param action action executed with the remote client
   */
  private static void withRemoteTigerProxyClient(
      final String clusterId, final java.util.function.Consumer<TigerRemoteProxyClient> action) {
    try (TigerRemoteProxyClient tigerRemoteProxyClient = createRemoteTigerProxyClient(clusterId)) {
      action.accept(tigerRemoteProxyClient);
    }
  }

  /**
   * Creates a REST client for the remote standalone Tiger Proxy configured with the supplied
   * cluster id.
   *
   * @param clusterId cluster identifier of the remote standalone Tiger Proxy
   * @return remote Tiger Proxy REST client
   */
  private static TigerRemoteProxyClient createRemoteTigerProxyClient(final String clusterId) {
    final TigerProxyServer tigerProxyServer =
        TigerDirector.getTigerTestEnvMgr()
            .findTigerProxyServerByClusterId(clusterId)
            .orElseThrow(
                () ->
                    new TigerProxyGlueException(
                        "Could not find a standalone Tiger Proxy with clusterId '"
                            + clusterId
                            + "'."));
    final String managementBaseUrl =
        tigerProxyServer
            .getHealthcheckUrl()
            .orElseThrow(
                () ->
                    new TigerTestEnvException(
                        "Tiger Proxy server '"
                            + tigerProxyServer.getServerId()
                            + "' does not expose a management URL."));
    return new TigerRemoteProxyClient(managementBaseUrl, TigerProxyConfiguration.builder().build());
  }

  /**
   * Adds a single resource to a remote standalone Tiger Proxy.
   *
   * @param tigerRemoteProxyClient remote Tiger Proxy REST client
   * @param resourceType resource type to create
   * @param jsonPayload JSON payload matching the selected resource type
   * @return created resource
   */
  private static Object addTigerProxyResource(
      final TigerRemoteProxyClient tigerRemoteProxyClient,
      final TigerProxyResourceType resourceType,
      final String jsonPayload) {
    final String resolvedJsonPayload = TigerGlobalConfiguration.resolvePlaceholders(jsonPayload);
    switch (resourceType) {
      case ROUTE:
        return tigerRemoteProxyClient.addRoute(
            TigerSerializationUtil.fromJson(resolvedJsonPayload, TigerProxyRoute.class));
      case MODIFICATION:
        return tigerRemoteProxyClient.addModificaton(
            TigerSerializationUtil.fromJson(
                resolvedJsonPayload, RbelModificationDescription.class));
      default:
        throw new TigerProxyGlueException(
            "Unsupported Tiger Proxy resource type: " + resourceType.getSingularExpression());
    }
  }

  /**
   * Removes a single resource from a remote standalone Tiger Proxy.
   *
   * @param tigerRemoteProxyClient remote Tiger Proxy REST client
   * @param resourceType resource type to remove
   * @param resourceIdentifier route id or modification name
   */
  private static void removeTigerProxyResource(
      final TigerRemoteProxyClient tigerRemoteProxyClient,
      final TigerProxyResourceType resourceType,
      final String resourceIdentifier) {
    switch (resourceType) {
      case ROUTE:
        tigerRemoteProxyClient.removeRoute(resourceIdentifier);
        return;
      case MODIFICATION:
        tigerRemoteProxyClient.removeModification(resourceIdentifier);
        return;
      default:
        throw new TigerProxyGlueException(
            "Unsupported Tiger Proxy resource type: " + resourceType.getSingularExpression());
    }
  }

  /**
   * Clears all resources of one type from a remote standalone Tiger Proxy.
   *
   * @param tigerRemoteProxyClient remote Tiger Proxy REST client
   * @param resourceType resource type to clear
   */
  private static void clearTigerProxyResources(
      final TigerRemoteProxyClient tigerRemoteProxyClient,
      final TigerProxyResourceType resourceType) {
    switch (resourceType) {
      case ROUTE:
        tigerRemoteProxyClient.clearAllRoutes();
        return;
      case MODIFICATION:
        tigerRemoteProxyClient.getModifications().stream()
            .map(RbelModificationDescription::getName)
            .forEach(tigerRemoteProxyClient::removeModification);
        return;
      default:
        throw new TigerProxyGlueException(
            "Unsupported Tiger Proxy resource type: " + resourceType.getSingularExpression());
    }
  }

  /**
   * Retrieves all resources of one type from a remote standalone Tiger Proxy.
   *
   * @param tigerRemoteProxyClient remote Tiger Proxy REST client
   * @param resourceType resource type to fetch
   * @return resource list
   */
  private static List<?> getTigerProxyResources(
      final TigerRemoteProxyClient tigerRemoteProxyClient,
      final TigerProxyResourceType resourceType) {
    switch (resourceType) {
      case ROUTE:
        return tigerRemoteProxyClient.getRoutes();
      case MODIFICATION:
        return tigerRemoteProxyClient.getModifications();
      default:
        throw new TigerProxyGlueException(
            "Unsupported Tiger Proxy resource type: " + resourceType.getSingularExpression());
    }
  }

  /**
   * Stores a value as pretty-printed JSON in the global Tiger configuration.
   *
   * @param variableName Tiger variable name
   * @param value value to serialize
   */
  private static void storeAsJson(final String variableName, final Object value) {
    TigerGlobalConfiguration.putValue(variableName, TigerSerializationUtil.toJson(value));
  }

  /**
   * Runtime exception raised for Tiger Proxy specific TGR failures.
   */
  static class TigerProxyGlueException extends RuntimeException {

    /**
     * Creates a new exception with the given message.
     *
     * @param message failure message
     */
    TigerProxyGlueException(final String message) {
      super(message);
    }
  }
}
