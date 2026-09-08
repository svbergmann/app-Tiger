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

import java.net.InetAddress;
import java.net.UnknownHostException;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class RbelInternetAddressParser {

  /**
   * Canonical name for every loopback address. Deliberately a constant instead of a reverse lookup:
   * the local hosts file decides which alias 127.0.0.1 resolves back to ("localhost",
   * "view-localhost", "kubernetes.docker.internal", ...), which would make recorded traffic depend
   * on the machine that recorded it.
   */
  public static final String LOOPBACK_HOSTNAME = "localhost";

  /**
   * Splits an address string into hostname and IP without ever consulting DNS. Resolution belongs
   * to {@link RbelInternetAddress#toInetAddress()}, the one place that caches it with an expiry.
   */
  public static RbelInternetAddress parseInetAddress(String addressString) {
    if (addressString == null || addressString.trim().isEmpty()) {
      throw new IllegalArgumentException("Address string cannot be null or empty.");
    }

    return parseInetAddressUncached(addressString);
  }

  private static RbelInternetAddress parseInetAddressUncached(String addressString) {
    int slashIndex = addressString.indexOf('/');

    if (slashIndex != -1) {
      return parseJavaHostnameAddressScheme(addressString, slashIndex);
    } else {
      return parseRegularHostname(addressString);
    }
  }

  private static boolean isLikelyIpAddress(String input) {
    if (input == null || input.isEmpty()) return false;
    char first = input.charAt(0);
    return Character.isDigit(first) || input.contains(":");
  }

  private static RbelInternetAddress parseRegularHostname(String addressString) {
    if (!isLikelyIpAddress(addressString)) {
      return new RbelInternetAddress(addressString, null);
    }
    try {
      // A literal. getByName parses the digits and does not consult DNS, so this stays local.
      InetAddress inetAddress = InetAddress.getByName(addressString);
      return new RbelInternetAddress(hostnameWithoutLookup(inetAddress), inetAddress.getAddress());
    } catch (UnknownHostException e) {
      if (addressString.equals(LOOPBACK_HOSTNAME)) {
        return new RbelInternetAddress(
            addressString, InetAddress.getLoopbackAddress().getAddress());
      }
      return new RbelInternetAddress(addressString, null);
    }
  }

  /**
   * Determines the hostname of an already resolved address without ever consulting the name
   * service. {@link InetAddress#toString()} renders the hostname the address was created with (an
   * empty string when it was built from raw bytes, as is the case for every accepted connection)
   * and is documented to skip the reverse lookup that {@link InetAddress#getHostName()} would
   * perform. That lookup blocks for up to the resolver timeout and yields whichever alias the local
   * hosts file happens to list first, so addresses without a hostname are described by their IP
   * instead - except for loopback, which always gets {@link #LOOPBACK_HOSTNAME}.
   */
  static String hostnameWithoutLookup(InetAddress inetAddress) {
    final String knownHostname = StringUtils.substringBefore(inetAddress.toString(), "/");
    if (!knownHostname.isEmpty()) {
      return knownHostname;
    }
    return inetAddress.isLoopbackAddress() ? LOOPBACK_HOSTNAME : null;
  }

  /**
   * Parses an address string in the Java hostname/address scheme (e.g., "hostname/ip-address").
   *
   * @param addressString
   * @param slashIndex
   * @return
   */
  private static RbelInternetAddress parseJavaHostnameAddressScheme(
      String addressString, int slashIndex) {
    String hostname = addressString.substring(0, slashIndex);
    String ipAddress = addressString.substring(slashIndex + 1);
    try {
      byte[] ipBytes = InetAddress.getByName(ipAddress).getAddress();
      return new RbelInternetAddress(StringUtils.isEmpty(hostname) ? ipAddress : hostname, ipBytes);
    } catch (UnknownHostException e) {
      return new RbelInternetAddress(hostname, null);
    }
  }
}
