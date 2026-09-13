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
package io.cucumber.core.plugin.progress;

import io.cucumber.java.BeforeAll;
import io.cucumber.java.en.Given;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class ProgressSteps {
  public static final AtomicInteger calls = new AtomicInteger();
  public static volatile boolean failBeforeAll;
  public static volatile boolean failSteps;
  public static volatile CountDownLatch release;

  @BeforeAll
  public static void beforeAll() {
    if (failBeforeAll) {
      throw new IllegalStateException("BeforeAll failed");
    }
  }

  @Given("a progress scenario")
  public void scenario() throws InterruptedException {
    if (calls.incrementAndGet() == 1 && release != null) {
      if (!release.await(10, TimeUnit.SECONDS)) {
        throw new IllegalStateException("Parallel progress was not published live");
      }
    }
    if (failSteps) {
      throw new AssertionError("Step failed");
    }
  }
}
