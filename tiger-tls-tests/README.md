# tiger-tls-tests

`tiger-tls-tests` is the in-repository TLS probe and compliance module for Tiger.
It provides active TLS client probes, server-side observation mode for DUT clients, structured evidence, and OpenSSL reproduction commands for the executed checks.

## What it covers

- built-in TLS profiles such as `connectivity`, `default`, and `strict-modern`
- protocol, cipher suite, ALPN, named group, and signature scheme scans
- TLS 1.2 renegotiation, session resumption, secure renegotiation, extended master secret, `encrypt_then_mac`, and fallback-SCSV probes
- OCSP stapling, unknown-extension tolerance, and malformed-record rejection
- one-shot TLS server observation where Tiger accepts a DUT client connection and records negotiated TLS parameters, SNI, ALPN, client certificates, and reproducible evidence

## How to use it

If you want to use the TLS checks from TGR/Cucumber steps, depend on `tiger-test-lib`.
The TLS glue is exposed from there and already delegates to this module.

```xml
<dependency>
    <groupId>de.gematik.test</groupId>
    <artifactId>tiger-test-lib</artifactId>
    <version>${tiger.version}</version>
    <scope>test</scope>
</dependency>
```

If you want to call the TLS runner directly from Java code, depend on `tiger-tls-tests`.

```xml
<dependency>
    <groupId>de.gematik.test</groupId>
    <artifactId>tiger-tls-tests</artifactId>
    <version>${tiger.version}</version>
    <scope>test</scope>
</dependency>
```

## Java API example

```java
import de.gematik.test.tiger.tlstests.TlsTestProfile;
import de.gematik.test.tiger.tlstests.TlsTestRequest;
import de.gematik.test.tiger.tlstests.TlsTestRunner;
import de.gematik.test.tiger.tlstests.TlsTestTarget;

TlsTestRunner runner = new TlsTestRunner();
var report =
    runner.run(
        TlsTestRequest.of(
            new TlsTestTarget("dut.example.org", 443, null),
            TlsTestProfile.STRICT_MODERN));

report.results().forEach(
    result -> {
      System.out.println(result.testCase() + ": " + result.verdict());
      result.evidence().primaryReproductionCommand().ifPresent(System.out::println);
    });
```

For deeper scans, use `TlsComplianceRunner`.
For DUT-client testing where Tiger should act as the TLS server, use `TlsServerObservationRunner`.

## Evidence

Every report carries `TlsProbeEvidence` with:

- reproduction commands, usually OpenSSL-based
- probe log entries
- notes that explain translation gaps between Tiger identities and OpenSSL command lines

This is intended for TGR evidence export and for manual re-checks after a failing scenario.

## Documentation

- TGR usage is documented in [doc/user_manual/tigerTestLibrary.adoc](../doc/user_manual/tigerTestLibrary.adoc)
- the repository overview links to the generated user manual from [README.md](../README.md)

## Local verification

```bash
mvn -Dmaven.repo.local=.m2 -pl tiger-tls-tests test -DskipITs
mvn -Dmaven.repo.local=.m2 -pl tiger-tls-tests -DskipITs=false verify
```
