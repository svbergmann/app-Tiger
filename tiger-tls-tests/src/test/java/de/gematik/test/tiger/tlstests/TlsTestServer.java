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

import java.math.BigInteger;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

final class TlsTestServer implements AutoCloseable {

  private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();

  enum CertificateValidity {
    VALID,
    EXPIRED
  }

  private final SSLServerSocket serverSocket;
  private final ExecutorService executorService = Executors.newSingleThreadExecutor();

  private TlsTestServer(SSLServerSocket serverSocket) {
    this.serverSocket = serverSocket;
  }

  static TlsTestServer start(CertificateValidity validity, String... enabledProtocols)
      throws Exception {
    final KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);

    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();
    final X509Certificate certificate = createCertificate(keyPair, validity);
    keyStore.setKeyEntry(
        "server", keyPair.getPrivate(), KEYSTORE_PASSWORD, new Certificate[] {certificate});

    final KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD);

    final SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());

    final SSLServerSocket serverSocket =
        (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(0);
    serverSocket.setEnabledProtocols(enabledProtocols);

    final TlsTestServer tlsTestServer = new TlsTestServer(serverSocket);
    tlsTestServer.startAcceptLoop();
    return tlsTestServer;
  }

  int port() {
    return serverSocket.getLocalPort();
  }

  private void startAcceptLoop() {
    executorService.submit(
        () -> {
          while (!serverSocket.isClosed()) {
            try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
              socket.setUseClientMode(false);
              socket.startHandshake();
            } catch (SocketException e) {
              if (!serverSocket.isClosed()) {
                throw e;
              }
            } catch (Exception e) {
              if (serverSocket.isClosed()) {
                return;
              }
            }
          }
        });
  }

  private static X509Certificate createCertificate(KeyPair keyPair, CertificateValidity validity)
      throws Exception {
    final Instant now = Instant.now();
    final Instant notBefore =
        validity == CertificateValidity.EXPIRED
            ? now.minus(5, ChronoUnit.DAYS)
            : now.minus(1, ChronoUnit.DAYS);
    final Instant notAfter =
        validity == CertificateValidity.EXPIRED
            ? now.minus(1, ChronoUnit.DAYS)
            : now.plus(5, ChronoUnit.DAYS);

    final X500Name subject = new X500Name("CN=Tiger TLS Test Server");
    final JcaX509v3CertificateBuilder certificateBuilder =
        new JcaX509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(notBefore),
            Date.from(notAfter),
            subject,
            keyPair.getPublic());
    final ContentSigner contentSigner =
        new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
    final X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

    return new JcaX509CertificateConverter().getCertificate(certificateHolder);
  }

  @Override
  public void close() throws Exception {
    serverSocket.close();
    executorService.shutdownNow();
  }
}
