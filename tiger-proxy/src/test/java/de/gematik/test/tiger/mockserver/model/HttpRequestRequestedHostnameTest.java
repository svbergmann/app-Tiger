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
package de.gematik.test.tiger.mockserver.model;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * {@link HttpRequest#requestedHostname()} feeds the connection-pool key, so a wrong answer either
 * collapses two virtual hosts into one pooled connection or splits one host across several.
 */
class HttpRequestRequestedHostnameTest {

  @Test
  void shouldPreferTheReceiverAddressOverTheHostHeader() {
    var request =
        new HttpRequest()
            .setReceiverAddress(new SocketAddress().withHost("receiver.example.com").withPort(443))
            .withHeader("Host", "header.example.com");

    assertThat(request.requestedHostname()).contains("receiver.example.com");
  }

  @Test
  void shouldFallBackToTheHostHeaderWithoutAReceiverAddress() {
    var request = new HttpRequest().withHeader("Host", "header.example.com");

    assertThat(request.requestedHostname()).contains("header.example.com");
  }

  @Test
  void shouldFallBackToTheHostHeaderWhenTheReceiverAddressHasNoHost() {
    var request =
        new HttpRequest()
            .setReceiverAddress(new SocketAddress().withPort(443))
            .withHeader("Host", "header.example.com");

    assertThat(request.requestedHostname()).contains("header.example.com");
  }

  @Test
  void shouldDropThePortFromTheHostHeader() {
    var request = new HttpRequest().withHeader("Host", "example.com:8443");

    assertThat(request.requestedHostname()).contains("example.com");
  }

  @Test
  void shouldUnwrapABracketedIpv6HostWithPort() {
    var request = new HttpRequest().withHeader("Host", "[::1]:8080");

    assertThat(request.requestedHostname()).contains("::1");
  }

  @Test
  void shouldUnwrapABracketedIpv6HostWithoutPort() {
    var request = new HttpRequest().withHeader("Host", "[2001:db8::1]");

    assertThat(request.requestedHostname()).contains("2001:db8::1");
  }

  @Test
  void shouldKeepABareIpAddress() {
    var request = new HttpRequest().withHeader("Host", "192.168.1.1:443");

    assertThat(request.requestedHostname()).contains("192.168.1.1");
  }

  @Test
  void shouldBeEmptyWithNeitherReceiverAddressNorHostHeader() {
    assertThat(new HttpRequest().requestedHostname()).isEmpty();
  }

  @Test
  void shouldBeEmptyForABlankHostHeader() {
    var request = new HttpRequest().withHeader("Host", "   ");

    assertThat(request.requestedHostname()).isEmpty();
  }

  /**
   * The point of this method over {@link HttpRequest#optionalSocketAddressFromHostHeader()}: it
   * hands back the name as written, case and all. A name that cannot resolve must come back
   * unchanged rather than cost a resolver timeout on the request hot path.
   */
  @Test
  void shouldReturnTheNameVerbatimWithoutResolvingIt() {
    var request =
        new HttpRequest().withHeader("Host", "no-such-host.invalid.testdriverApi-X-ORG:9999");

    assertThat(request.requestedHostname()).contains("no-such-host.invalid.testdriverApi-X-ORG");
  }

  /**
   * A literal IP must survive as a literal.
   *
   * <p>{@code setReceiverAddress} builds an {@link java.net.InetSocketAddress} to split host from
   * port, and reading the host back with {@code getHostName()} reverse-resolves a literal into
   * whatever alias the machine's hosts file offers - measured turning {@code 127.0.0.1} into {@code
   * view-localhost} on a developer machine, 39 times in one scenario. That is a blocking lookup per
   * request whose only product is a machine-dependent name.
   */
  @Test
  void aLiteralIpReceiverAddressMustNotBeTurnedIntoAHostname() {
    var request = new HttpRequest().setReceiverAddress(true, "127.0.0.1", 8092);

    assertThat(request.getReceiverAddress().getHost()).isEqualTo("127.0.0.1");
    assertThat(request.requestedHostname()).contains("127.0.0.1");
  }

  /**
   * The other half of the contract, and what keeps virtual hosts apart: a host given as a name is
   * carried through untouched, so two vhosts sharing one ingress IP keep separate pool keys.
   */
  @Test
  void aNamedReceiverAddressMustBeKeptVerbatim() {
    var request = new HttpRequest().setReceiverAddress(true, "idp.example.com", 8443);

    assertThat(request.getReceiverAddress().getHost()).isEqualTo("idp.example.com");
    assertThat(request.getReceiverAddress().getPort()).isEqualTo(8443);
    assertThat(request.requestedHostname()).contains("idp.example.com");
  }

  @Test
  void receiverAddressShouldTakeThePortFromTheHostWhenGiven() {
    var request = new HttpRequest().setReceiverAddress(true, "127.0.0.1:9443", null);

    assertThat(request.getReceiverAddress().getHost()).isEqualTo("127.0.0.1");
    assertThat(request.getReceiverAddress().getPort()).isEqualTo(9443);
  }
}
