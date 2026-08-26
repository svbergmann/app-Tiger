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
package de.gematik.rbellogger.data;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.rbellogger.data.core.RbelFacet;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.val;
import org.junit.jupiter.api.Test;

/**
 * Facet removal goes through {@code RbelElement.dropFacetInstance}, which is identity-based on
 * purpose. Facets compare by content, so an element can legitimately hold two that are equal but
 * distinct, and a content-based removal would drop whichever came first rather than the one the
 * caller passed in.
 *
 * <p>Removal also has to keep notifying: {@code facets} is an {@code ObservableQueue} whose whole
 * job is to bump the facet-metadata version, and a removal path that bypasses the queue's overrides
 * leaves rendered output stale without failing anything.
 */
class RbelElementFacetRemovalTest {

  /**
   * Content-based equality, as records give for free - the situation the identity check exists for.
   */
  private record LabelFacet(String label) implements RbelFacet {}

  private static final LabelFacet MARKER = new LabelFacet("same");

  @Test
  void removeFacetShouldDropTheInstancePassedInAndNotAnEqualOne() {
    val element = new RbelElement(null, null);
    val first = new LabelFacet("same");
    val second = new LabelFacet("same");
    assertThat(first).isEqualTo(second).isNotSameAs(second);
    element.addFacet(first);
    element.addFacet(second);

    element.removeFacet(second);

    assertThat(element.getFacets()).hasSize(1);
    assertThat(element.getFacets().iterator().next()).isSameAs(first);
  }

  /**
   * The shape the converters use: add a facet, then undo that exact addition when parsing turns out
   * to have failed - see {@code RbelAsn1Converter}, which rolls back this way in three places.
   *
   * <p>Removing by equality would drop whichever equal facet came first instead. No facet in the
   * codebase is equal by content yet distinguishable by anything outside its equality, so that
   * substitution is not observable and this pins predictability rather than a fixed defect: "remove
   * this instance" should not quietly mean "remove something like it". The one case equality would
   * genuinely get wrong is removing the same instance twice, which takes out a twin rather than
   * doing nothing.
   */
  @Test
  void rollingBackAnAdditionShouldRemoveTheAddedInstanceNotAnEqualOlderOne() {
    val element = new RbelElement(null, null);
    val established = new LabelFacet("same");
    element.addFacet(established);

    val speculative = new LabelFacet("same");
    element.addFacet(speculative);
    element.removeFacet(speculative);

    assertThat(element.getFacets()).hasSize(1);
    assertThat(element.getFacets().iterator().next()).isSameAs(established);
  }

  @Test
  void removeFacetShouldLeaveOtherFacetTypesAlone() {
    val element = new RbelElement(null, null);
    val label = new LabelFacet("a");
    val other = new OtherFacet(1);
    element.addFacet(label);
    element.addFacet(other);

    element.removeFacet(label);

    assertThat(element.getFacets()).containsExactly(other);
  }

  @Test
  void removeFacetsOfTypeShouldDropEveryFacetOfThatType() {
    val element = new RbelElement(null, null);
    element.addFacet(new LabelFacet("a"));
    element.addFacet(new LabelFacet("b"));
    val survivor = new OtherFacet(7);
    element.addFacet(survivor);

    element.removeFacetsOfType(LabelFacet.class);

    assertThat(element.getFacets()).containsExactly(survivor);
  }

  @Test
  void addOrReplaceFacetShouldSwapTheFacetOfThatTypeRatherThanAppend() {
    val element = new RbelElement(null, null);
    element.addFacet(new LabelFacet("old"));
    val replacement = new LabelFacet("new");

    element.addOrReplaceFacet(replacement);

    assertThat(element.getFacets()).hasSize(1);
    assertThat(element.getFacet(LabelFacet.class)).containsSame(replacement);
  }

  @Test
  void addOrReplaceFacetShouldAddWhenNoFacetOfThatTypeIsPresent() {
    val element = new RbelElement(null, null);
    val facet = new LabelFacet("only");

    element.addOrReplaceFacet(facet);

    assertThat(element.getFacet(LabelFacet.class)).containsSame(facet);
  }

  /**
   * The regression guard: removal has to reach the listener. A removal implemented with a method
   * the {@code ObservableQueue} does not override notifies nobody, and the only visible symptom is
   * a stale hash in the rendered report.
   */
  @Test
  void removingAFacetShouldNotifyMetadataListeners() {
    val element = new RbelElement(null, null);
    element.addFacet(MARKER);
    val notifications = new AtomicInteger();
    element.addFacetMetadataUpdateListener(notifications::incrementAndGet);

    element.removeFacet(MARKER);

    assertThat(notifications).hasValueGreaterThan(0);
  }

  @Test
  void removingAFacetOnAChildShouldNotifyListenersOnTheRoot() {
    val root = new RbelElement(null, null);
    val child = new RbelElement(null, root);
    child.addFacet(MARKER);
    val notifications = new AtomicInteger();
    root.addFacetMetadataUpdateListener(notifications::incrementAndGet);

    child.removeFacet(MARKER);

    assertThat(notifications).hasValueGreaterThan(0);
  }

  private record OtherFacet(int id) implements RbelFacet {}
}
