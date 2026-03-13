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

import java.util.List;
import java.util.Optional;

/**
 * Captures reproducible evidence for one TLS probe execution.
 *
 * @param reproductionCommands shell commands that help reproduce the probe outside Tiger
 * @param notes explanatory notes about the probe and the reproduction limits
 * @param logEntries structured execution log entries captured during the probe
 */
public record TlsProbeEvidence(
    List<String> reproductionCommands, List<String> notes, List<String> logEntries) {

  /**
   * Creates an empty evidence object.
   *
   * @return empty evidence object
   */
  public static TlsProbeEvidence empty() {
    return new TlsProbeEvidence(List.of(), List.of(), List.of());
  }

  /**
   * Creates an immutable evidence object.
   *
   * @param reproductionCommands shell commands that help reproduce the probe outside Tiger
   * @param notes explanatory notes about the probe and the reproduction limits
   * @param logEntries structured execution log entries captured during the probe
   */
  public TlsProbeEvidence {
    reproductionCommands =
        List.copyOf(reproductionCommands == null ? List.of() : reproductionCommands);
    notes = List.copyOf(notes == null ? List.of() : notes);
    logEntries = List.copyOf(logEntries == null ? List.of() : logEntries);
  }

  /**
   * Returns the first reproduction command when one is available.
   *
   * @return optional primary reproduction command
   */
  public Optional<String> primaryReproductionCommand() {
    return reproductionCommands.stream().findFirst();
  }
}
