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

import java.util.ArrayList;
import java.util.List;

/**
 * Mutable collector used to assemble immutable {@link TlsProbeEvidence} instances.
 */
final class TlsProbeEvidenceBuilder {

  private final List<String> reproductionCommands = new ArrayList<>();
  private final List<String> notes = new ArrayList<>();
  private final List<String> logEntries = new ArrayList<>();

  /**
   * Adds one reproduction command.
   *
   * @param reproductionCommand shell command to add
   * @return this builder
   */
  TlsProbeEvidenceBuilder addReproductionCommand(String reproductionCommand) {
    if (reproductionCommand != null && !reproductionCommand.isBlank()) {
      reproductionCommands.add(reproductionCommand);
    }
    return this;
  }

  /**
   * Adds one explanatory note.
   *
   * @param note explanatory note to add
   * @return this builder
   */
  TlsProbeEvidenceBuilder addNote(String note) {
    if (note != null && !note.isBlank()) {
      notes.add(note);
    }
    return this;
  }

  /**
   * Adds one structured execution log line.
   *
   * @param logEntry structured execution log line
   * @return this builder
   */
  TlsProbeEvidenceBuilder addLogEntry(String logEntry) {
    if (logEntry != null && !logEntry.isBlank()) {
      logEntries.add(logEntry);
    }
    return this;
  }

  /**
   * Builds the immutable evidence object.
   *
   * @return immutable probe evidence
   */
  TlsProbeEvidence build() {
    return new TlsProbeEvidence(reproductionCommands, notes, logEntries);
  }
}
