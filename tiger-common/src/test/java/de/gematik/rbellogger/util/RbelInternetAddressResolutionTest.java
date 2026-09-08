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
package de.gematik.rbellogger.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.net.UnknownHostException;
import lombok.val;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Where hostname resolution happens, and where it must not. */
class RbelInternetAddressResolutionTest {

  @BeforeEach
  @AfterEach
  void useTheRealResolverAndAnEmptyCache() {
    RbelInternetAddress.resetHostnameResolver();
  }

  @Test
  void aBareHostnameShouldBeCarriedThroughUnresolved() {
    val parsed = RbelInternetAddressParser.parseInetAddress("localhost");

    assertThat(parsed.getHostname()).isEqualTo("localhost");
    assertThat(parsed.getIpAddress())
        .as("parsing must not consult DNS - the IP is filled in on demand, through the TTL cache")
        .isNull();
  }

  @Test
  void anUnresolvedHostnameShouldStillResolveOnDemand() {
    val parsed = RbelInternetAddressParser.parseInetAddress("localhost");

    assertThat(parsed.toInetAddress())
        .get()
        .extracting(InetAddress::getAddress)
        .isEqualTo(new byte[] {127, 0, 0, 1});
  }

  /** An IP literal is parsed locally - {@code getByName} on digits does not hit a resolver. */
  @Test
  void anIpLiteralShouldBeParsedWithoutResolving() {
    val parsed = RbelInternetAddressParser.parseInetAddress("10.11.12.13");

    assertThat(parsed.getIpAddress()).isEqualTo(new byte[] {10, 11, 12, 13});
    assertThat(parsed.getHostname())
        .as("a literal carries no name - inventing one would need a reverse lookup")
        .isNull();
  }

  @Test
  void aLoopbackLiteralShouldKeepTheLoopbackName() {
    val parsed = RbelInternetAddressParser.parseInetAddress("127.0.0.1");

    assertThat(parsed.getIpAddress()).isEqualTo(new byte[] {127, 0, 0, 1});
    assertThat(parsed.getHostname()).isNotBlank();
  }

  @Test
  void theHostSlashIpFormShouldCarryBothHalvesWithoutResolving() {
    val parsed = RbelInternetAddressParser.parseInetAddress("someserver.local/10.11.12.13");

    assertThat(parsed.getHostname()).isEqualTo("someserver.local");
    assertThat(parsed.getIpAddress()).isEqualTo(new byte[] {10, 11, 12, 13});
  }

  @Test
  void anUnresolvableHostnameShouldParseAndSimplyNotResolve() {
    val parsed = RbelInternetAddressParser.parseInetAddress("no-such-host.invalid");

    assertThat(parsed.getHostname()).isEqualTo("no-such-host.invalid");
    assertThat(parsed.getIpAddress()).isNull();
    assertThat(parsed.toInetAddress()).isEmpty();
  }

  @Test
  void toStringShouldFillInTheIpForAResolvableName() {
    val parsed = RbelInternetAddressParser.parseInetAddress("localhost");

    assertThat(parsed.toString()).isEqualTo("localhost/127.0.0.1");
  }

  /** Rendering must never fail or hang on a host that cannot resolve - it prints what it knows. */
  @Test
  void toStringShouldPrintJustTheNameWhenItCannotResolve() {
    val parsed = RbelInternetAddressParser.parseInetAddress("no-such-host.invalid");

    assertThat(parsed.toString()).isEqualTo("no-such-host.invalid");
  }

  @Test
  void toStringShouldPrintJustTheAddressWhenThereIsNoName() {
    val parsed = RbelInternetAddressParser.parseInetAddress("10.11.12.13");

    assertThat(parsed.toString()).isEqualTo("10.11.12.13");
  }

  @Test
  void repeatedParsesMustNotFreezeTheAddressForTheLifeOfTheJvm() {
    val first = RbelInternetAddressParser.parseInetAddress("localhost");
    val second = RbelInternetAddressParser.parseInetAddress("localhost");

    assertThat(first.getIpAddress()).isNull();
    assertThat(second.getIpAddress()).isNull();

    RbelInternetAddress.clearResolvedHostnameCache();

    assertThat(second.toInetAddress())
        .as(
            "after the cache is dropped the host is asked again rather than answered from a fixture")
        .isPresent();
  }

  @Test
  void anAddressParsedOnceShouldFollowTheHostWhenItMoves() throws Exception {
    val movingHost = "localhost";
    val oldLocation = InetAddress.getByAddress(new byte[] {10, 0, 0, 1});
    val newLocation = InetAddress.getByAddress(new byte[] {10, 0, 0, 2});

    RbelInternetAddress.setHostnameResolver(host -> oldLocation);
    val parsedOnce = RbelInternetAddressParser.parseInetAddress(movingHost);
    assertThat(parsedOnce.toInetAddress()).contains(oldLocation);

    RbelInternetAddress.setHostnameResolver(host -> newLocation);

    assertThat(parsedOnce.toInetAddress())
        .as(
            "the same parsed address must now point at the new location - if the IP were captured"
                + " at parse time it would still answer with the old one, and the proxy would keep"
                + " connecting there")
        .contains(newLocation);
  }

  /** The rendered form has to follow the move too, or reports name an address nobody is using. */
  @Test
  void toStringShouldFollowTheHostWhenItMoves() throws Exception {
    val movingHost = "localhost";

    RbelInternetAddress.setHostnameResolver(
        host -> InetAddress.getByAddress(new byte[] {10, 0, 0, 1}));
    val parsedOnce = RbelInternetAddressParser.parseInetAddress(movingHost);
    assertThat(parsedOnce).hasToString(movingHost + "/10.0.0.1");

    RbelInternetAddress.setHostnameResolver(
        host -> InetAddress.getByAddress(new byte[] {10, 0, 0, 2}));

    assertThat(parsedOnce).hasToString(movingHost + "/10.0.0.2");
  }

  @Test
  void oneHostShouldBeEqualToItselfWhetherOrNotTheIpIsFilledIn() {
    val fromName = new RbelInternetAddress("localhost", null);
    val fromLiteral = RbelInternetAddressParser.parseInetAddress("127.0.0.1");

    assertThat(fromLiteral.getHostname())
        .as("a loopback literal is parsed with the loopback name attached")
        .isEqualTo("localhost");
    assertThat(fromName)
        .as("same host, one half filled in - these must not be two different addresses")
        .isEqualTo(fromLiteral)
        .hasSameHashCodeAs(fromLiteral);
  }

  /** Host names are case-insensitive (RFC 4343), so one host must not be two addresses. */
  @Test
  void hostnamesShouldBeComparedCaseInsensitively() {
    val upper = new RbelInternetAddress("IDP.Example.COM", null);
    val lower = new RbelInternetAddress("idp.example.com", null);

    assertThat(upper).isEqualTo(lower).hasSameHashCodeAs(lower);
  }

  /**
   * The property ADR 024 is about: the name decides, so two virtual hosts sharing one ingress IP
   * stay distinct. A host that has moved likewise stays the same host.
   */
  @Test
  void differentNamesShouldStayDistinctEvenBehindOneIp() {
    val oneIp = new byte[] {10, 0, 0, 1};

    assertThat(new RbelInternetAddress("vhost-a.example.com", oneIp))
        .isNotEqualTo(new RbelInternetAddress("vhost-b.example.com", oneIp));
    assertThat(new RbelInternetAddress("moved.example.com", oneIp))
        .as("the same name is the same host wherever it now points")
        .isEqualTo(new RbelInternetAddress("moved.example.com", new byte[] {10, 0, 0, 2}));
  }

  /**
   * Unnamed addresses fall back to their bytes, and are never equal to a named one - telling those
   * apart would need a lookup, and equality must not perform I/O. This is also what keeps {@code
   * hashCode} consistent, since the two kinds hash on different fields.
   */
  @Test
  void unnamedAddressesShouldCompareOnTheirBytesAndNeverMatchANamedOne() {
    val unnamed = new RbelInternetAddress(null, new byte[] {10, 0, 0, 1});

    assertThat(unnamed)
        .isEqualTo(new RbelInternetAddress(null, new byte[] {10, 0, 0, 1}))
        .hasSameHashCodeAs(new RbelInternetAddress(null, new byte[] {10, 0, 0, 1}))
        .isNotEqualTo(new RbelInternetAddress(null, new byte[] {10, 0, 0, 2}))
        .isNotEqualTo(new RbelInternetAddress("named.example.com", new byte[] {10, 0, 0, 1}));
  }

  /** A resolver that fails must leave rendering intact rather than propagate. */
  @Test
  void aResolverFailureShouldDegradeToTheNameAlone() {
    RbelInternetAddress.setHostnameResolver(
        host -> {
          throw new UnknownHostException(host);
        });

    val parsed = RbelInternetAddressParser.parseInetAddress("gone.example.com");

    assertThat(parsed.toInetAddress()).isEmpty();
    assertThat(parsed).hasToString("gone.example.com");
  }
}
