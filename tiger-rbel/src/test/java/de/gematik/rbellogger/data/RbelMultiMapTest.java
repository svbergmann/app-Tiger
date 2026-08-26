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
package de.gematik.rbellogger.data;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class RbelMultiMapTest {

  @Test
  void entriesShouldKeepInsertionOrderAcrossRepeatedKeys() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");
    map.put("b", "2");
    map.put("a", "3");

    assertThat(map.entries())
        .extracting(Map.Entry::getKey, Map.Entry::getValue)
        .containsExactly(
            org.assertj.core.groups.Tuple.tuple("a", "1"),
            org.assertj.core.groups.Tuple.tuple("b", "2"),
            org.assertj.core.groups.Tuple.tuple("a", "3"));
  }

  @Test
  void getShouldReturnFirstValueAndGetAllShouldReturnAllInOrder() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");
    map.put("a", "2");

    assertThat(map).containsEntry("a", "1");
    assertThat(map.getAll("a")).containsExactly("1", "2");
    assertThat(map.get("missing")).isNull();
    assertThat(map.getAll("missing")).isEmpty();
  }

  @Test
  void removeShouldDropEveryValueForThatKey() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");
    map.put("a", "2");
    map.put("b", "3");

    assertThat(map.remove("a")).isEqualTo("1");
    assertThat(map.containsKey("a")).isFalse();
    assertThat(map).hasSize(1);
  }

  @Test
  @SuppressWarnings("removal")
  void unsupportedViewsShouldThrowRatherThanLoseOrdering() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");

    assertThatThrownBy(map::values).isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(map::entrySet).isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  @SuppressWarnings("removal")
  void getValuesShouldHandOutASnapshotRatherThanTheBackingCollection() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");
    map.put("b", "2");

    var snapshot = map.getValues();
    assertThat(snapshot).extracting(Map.Entry::getValue).containsExactly("1", "2");

    snapshot.clear();
    assertThat(map).as("Mutating the snapshot must not affect the map").hasSize(2);

    map.put("c", "3");
    assertThat(snapshot).as("The snapshot must not see later insertions").isEmpty();
  }

  /**
   * Guards the TGR-2201 regression: equality must stay identity-based. Roughly two dozen facets
   * embed an RbelMultiMap in a generated {@code equals}, and RbelElement removes facets by equality
   * - with content equality two structurally identical facets become interchangeable and the wrong
   * instance is removed.
   */
  @Test
  void mapsWithTheSameEntriesInTheSameOrderShouldBeEqual() {
    var first = new RbelMultiMap<String>();
    first.put("a", "1");
    first.put("b", "2");
    var second = new RbelMultiMap<String>();
    second.put("a", "1");
    second.put("b", "2");

    assertThat(first).isEqualTo(second);
    assertThat(first).hasSameHashCodeAs(second);
  }

  @Test
  void orderShouldBePartOfEquality() {
    var first = new RbelMultiMap<String>();
    first.put("a", "1");
    first.put("b", "2");
    var reversed = new RbelMultiMap<String>();
    reversed.put("b", "2");
    reversed.put("a", "1");

    assertThat(first).isNotEqualTo(reversed);
  }

  /**
   * Pins the snapshot semantics of {@link RbelMultiMap#stream()}. Streaming the backing store
   * directly would avoid an O(n) copy, but converters add children to a node while walking it, and
   * a live view turns that into a ConcurrentModificationException.
   */
  @Test
  void streamMustToleratePutsWhileItIsBeingConsumed() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");
    map.put("b", "2");

    assertThatNoException()
        .as("a converter adding a child while traversing must not blow up the traversal")
        .isThrownBy(() -> map.stream().forEach(entry -> map.put(entry.getKey() + "-child", "x")));

    assertThat(map.size()).isEqualTo(4);
  }

  @Test
  void iteratorRemoveShouldMutateTheMap() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");
    map.put("b", "2");

    var iterator = map.iterator();
    while (iterator.hasNext()) {
      if ("a".equals(iterator.next().getKey())) {
        iterator.remove();
      }
    }

    assertThat(map.containsKey("a"))
        .as("iterator() walks the backing store, so remove() must reach the map itself")
        .isFalse();
    assertThat(map.size()).isEqualTo(1);
  }

  @Test
  void mapsWithDifferentContentShouldNotBeEqual() {
    var first = new RbelMultiMap<String>();
    first.put("a", "1");
    var second = new RbelMultiMap<String>();
    second.put("a", "2");

    assertThat(first).isNotEqualTo(second);
  }

  @Test
  void collectorShouldGatherEntriesInEncounterOrder() {
    var collected =
        Stream.of(Map.entry("a", "1"), Map.entry("b", "2"), Map.entry("a", "3"))
            .collect(RbelMultiMap.collector());

    assertThat(collected.entries()).extracting(Map.Entry::getValue).containsExactly("1", "2", "3");
  }

  @Test
  void entriesShouldNotSeeLaterAdditions() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");
    var snapshot = map.entries();

    map.put("a", "2");

    assertThat(snapshot).hasSize(1);
  }

  @Test
  void entriesShouldSurviveRemovalOfWhatTheyHold() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");
    var snapshot = map.entries();

    map.removeAll("a");

    assertThat(snapshot).hasSize(1);
    assertThat(snapshot.get(0).getValue()).isEqualTo("1");
  }

  @Test
  void entriesShouldBeImmutable() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");

    assertThatThrownBy(() -> map.entries().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  /** Decides whether the copies may use {@code List.copyOf}, which rejects null elements. */
  @Test
  void aNullValueShouldSurviveBeingStoredAndReadBack() {
    var map = new RbelMultiMap<String>();
    map.put("a", null);

    assertThatNoException().isThrownBy(() -> map.getAll("a"));
    assertThatNoException().isThrownBy(map::entries);
    assertThat(map.getAll("a")).containsExactly((String) null);
  }

  @Test
  void getAllShouldNotSeeLaterAdditions() {
    var map = new RbelMultiMap<String>();
    map.put("a", "1");
    var sublist = map.getAll("a");

    map.put("a", "2");

    assertThat(sublist).hasSize(1);
  }
}
