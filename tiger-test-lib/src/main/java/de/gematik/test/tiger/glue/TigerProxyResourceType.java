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

import java.util.Arrays;

/**
 * Supported remote Tiger Proxy resource types exposed through TGR steps.
 */
public enum TigerProxyResourceType {
  ROUTE("route", "routes"),
  MODIFICATION("modification", "modifications");

  private final String singularExpression;
  private final String pluralExpression;

  /**
   * Creates a resource type with its singular and plural step expressions.
   *
   * @param singularExpression singular step expression
   * @param pluralExpression plural step expression
   */
  TigerProxyResourceType(final String singularExpression, final String pluralExpression) {
    this.singularExpression = singularExpression;
    this.pluralExpression = pluralExpression;
  }

  /**
   * Resolves the enum from the step expression used in a Cucumber step.
   *
   * @param expression singular or plural resource name from the step
   * @return matching resource type
   * @throws IllegalArgumentException if the expression is unknown
   */
  public static TigerProxyResourceType fromExpression(final String expression) {
    return Arrays.stream(values())
        .filter(type -> type.matches(expression))
        .findFirst()
        .orElseThrow(
            () -> new IllegalArgumentException("Unsupported Tiger Proxy resource type: " + expression));
  }

  /**
   * Checks whether the supplied step expression belongs to this resource type.
   *
   * @param expression singular or plural resource name from the step
   * @return {@code true} if the expression maps to this type
   */
  public boolean matches(final String expression) {
    return singularExpression.equalsIgnoreCase(expression)
        || pluralExpression.equalsIgnoreCase(expression);
  }

  /**
   * Returns the singular resource name used in log output and exceptions.
   *
   * @return singular resource name
   */
  public String getSingularExpression() {
    return singularExpression;
  }
}
