Feature: TLS test steps

  Scenario: Run a built-in TLS profile against a TLS server
    When TGR reset TLS test configuration
    And TGR enable TLS trust-all certificate mode
    And TGR run TLS test profile strict-modern against host "dut.example.org" on port 443
    Then TGR assert TLS overall verdict is passed
    And TGR assert TLS test SUPPORTS_TLS_1_3 is passed
    And TGR assert TLS test HANDSHAKE OpenSSL command matches ".*openssl s_client.*"

  Scenario: Scan protocol and cipher-suite support
    When TGR reset TLS test configuration
    And TGR scan TLS protocols "TLSv1.2, TLSv1.3" against host "dut.example.org" on port 443
    Then TGR assert last TLS protocol scan accepts "TLSv1.2"
    And TGR assert last TLS protocol scan accepts "TLSv1.3"
    And TGR assert TLS protocol scan for "TLSv1.3" OpenSSL command matches ".*-tls1_3.*"
    When TGR scan TLS cipher suites "TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384" against host "dut.example.org" on port 443
    Then TGR assert last TLS cipher suite scan accepts "TLS_AES_128_GCM_SHA256"

  Scenario: Probe specific TLS behavior and store structured evidence
    When TGR reset TLS test configuration
    And TGR run TLS 1.2 session resumption probe against host "dut.example.org" on port 443
    Then TGR assert last TLS behavior probe is passed
    And TGR assert last TLS behavior probe OpenSSL command matches ".*sess_out.*"
    When TGR store last TLS behavior probe in local variable "tls.behavior.report"

  Scenario: Observe one DUT client against Tiger acting as TLS server
    When TGR reset TLS server observation configuration
    And TGR set TLS server identity to "{tls.server.identity}"
    And TGR set TLS server application protocols to "h2, http/1.1"
    And TGR require TLS server client certificates
    And TGR set TLS server trust identity to "{tls.client.ca}"
    And TGR start TLS server observation on an ephemeral port
    And TGR store TLS server observation port in local variable "tls.observation.port"
    # Configure the DUT client to connect to 127.0.0.1:{tls.observation.port}.
    And TGR await last TLS server observation
    Then TGR assert last TLS server observation is passed
    And TGR assert last TLS server observation negotiated application protocol "h2"
    And TGR assert last TLS server observation contains client certificate
    And TGR assert last TLS server observation client certificate subject matches ".*CN=.*"
    And TGR assert last TLS server observation remote address matches ".+:[0-9]+"
    And TGR assert last TLS server observation OpenSSL command matches ".*openssl s_client.*"
