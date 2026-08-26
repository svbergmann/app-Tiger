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

import de.gematik.rbellogger.data.RbelMultiMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.NonNull;

/**
 * Enables the usage of the RbelPathExecutor. The methods are called by the RbelPathExecutor, but
 * not only. The description however focuses on that use-case
 */
public abstract class RbelPathAble<SELF extends RbelPathAble<SELF>> {

  public abstract Optional<SELF> getFirst(String key);

  public abstract SELF getParentNode();

  public abstract List<SELF> getAll(String subkey);

  public List<SELF> getChildNodes() {
    return getChildNodesStream().toList();
  }

  public Stream<SELF> getChildNodesStream() {
    return getChildNodesWithKeyStream().map(Map.Entry::getValue);
  }

  public abstract @NonNull Stream<Map.Entry<String, SELF>> getChildNodesWithKeyStream();

  public RbelMultiMap<SELF> getChildNodesWithKey() {
    return getChildNodesWithKeyStream().collect(RbelMultiMap.collector());
  }

  public abstract Optional<String> getKey();

  public abstract String getRawStringContent();

  public abstract List<SELF> findRbelPathMembers(String rbelPath);

  /**
   * Should return the list of search-relevant nodes. Normally this would be the identity (the
   * default implementation given here), but for virtual nodes (content-nodes in a rbel-tree for
   * example) that should not be part of the actual search-tree the child-nodes should be returned.
   */
  @SuppressWarnings("java:S1452")
  public List<? extends RbelPathAble<SELF>> descendToContentNodeIfAdvised() {
    return List.of(this);
  }

  /** Should this element be present in the final RbelPath results? */
  public boolean shouldElementBeKeptInFinalResult() {
    return true;
  }

  public String findNodePath() {
    var keyList = new LinkedList<String>();
    RbelPathAble<?> currentNode = this;
    RbelPathAble<?> parent = currentNode.getParentNode();
    while (parent != null) {
      currentNode.findKeyInParentElement().ifPresent(keyList::addFirst);
      currentNode = parent;
      parent = parent.getParentNode();
    }
    return String.join(".", keyList);
  }

  public Optional<String> findKeyInParentElement() {
    return Optional.ofNullable(getParentNode()).stream()
        .flatMap(RbelPathAble::getChildNodesWithKeyStream)
        .filter(e -> e.getValue() == this)
        .map(Map.Entry::getKey)
        .findFirst();
  }
}
