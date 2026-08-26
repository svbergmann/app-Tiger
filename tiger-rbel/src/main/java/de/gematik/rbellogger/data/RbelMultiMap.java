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

import com.google.common.collect.LinkedListMultimap;
import com.google.common.collect.ListMultimap;
import java.util.*;
import java.util.stream.Collector;
import java.util.stream.Stream;
import lombok.NonNull;

/**
 * Ordered multi-map: a key may repeat, and iteration yields entries in insertion order.
 *
 * <p>The access pattern that shapes this class: entries are appended one at a time while something
 * is being built, and are afterwards read many times - in order for traversal and rendering, by key
 * for lookups. Removal happens rarely.
 *
 * <p>Both rbel trees hold their named children this way, the parse tree of {@link RbelElement} and
 * the writer's tree of {@link de.gematik.rbellogger.writer.tree.RbelContentTreeNode}, but nothing
 * here is specific to either.
 *
 * <p>{@link LinkedListMultimap} fits that exactly: it iterates all entries in insertion order,
 * allows a key to repeat, and still indexes keys so lookups stay constant-time for wide nodes such
 * as large JSON objects or header lists.
 *
 * <p>Two instances are equal when they hold the same entries in the same order. {@code equals} and
 * {@code hashCode} are written out rather than generated so that equality is defined by the entries
 * themselves rather than by the identity of the backing multimap.
 *
 * <p>Note that the hash therefore changes as entries are appended. That is fine for the way these
 * maps are used - they are held by nodes, never used as keys themselves - but do not park one in a
 * {@link java.util.HashSet} and keep mutating it.
 *
 * <p><strong>Thread safety:</strong> this class is <em>not</em> thread-safe, and never has been.
 * Callers needing concurrent access have to arrange it themselves - see {@code
 * doc/adr/023_rbel_conversion_thread_ownership.md} for why wrapping this class is not the answer.
 */
public class RbelMultiMap<T> implements Map<String, T> {

  public static <T> Collector<Entry<String, T>, RbelMultiMap<T>, RbelMultiMap<T>> collector() {
    return Collector.of(
        RbelMultiMap::new,
        RbelMultiMap::put,
        (m1, m2) -> {
          m1.putAll(m2);
          return m1;
        });
  }

  private final ListMultimap<String, T> values = LinkedListMultimap.create();

  /**
   * @deprecated Prefer {@link #entries()}, {@link #stream()}, {@link #getAll(String)} or {@link
   *     #keySet()}.
   */
  @Deprecated(forRemoval = true)
  public Queue<Entry<String, T>> getValues() {
    return new ArrayDeque<>(values.entries());
  }

  @Override
  public int size() {
    return values.size();
  }

  @Override
  public boolean isEmpty() {
    return values.isEmpty();
  }

  @Override
  public boolean containsKey(Object key) {
    return values.containsKey(key);
  }

  @Override
  public boolean containsValue(Object value) {
    return values.containsValue(value);
  }

  /** Returns the first value associated with the key, or {@code null} if none. */
  @Override
  public T get(Object key) {
    List<T> list = values.get((String) key);
    return list.isEmpty() ? null : list.get(0);
  }

  /**
   * The values stored under this key, in insertion order: an immutable list, detached from the map,
   * so later puts and removals do not show up in it. A stored value may be null.
   */
  public List<T> getAll(String key) {
    // Copied because values.get(key) is a live sub-list of the multimap - wrapping that in
    // unmodifiableList would only stop the caller writing to it while it went on changing
    // underneath them, which is worse than either a plain view or a plain snapshot because it
    // looks like the latter. stream().toList() rather than the quicker List.copyOf used by
    // entries(): the elements here are the stored values, and a null one is permitted.
    return values.get(key).stream().toList();
  }

  /** Appends the value; never replaces. Returns {@code null} because nothing is displaced. */
  @Override
  public T put(String key, T value) {
    values.put(key, value);
    return null;
  }

  /** Appends the value; never replaces. Returns {@code null} because nothing is displaced. */
  public T put(Entry<String, T> value) {
    values.put(value.getKey(), value.getValue());
    return null;
  }

  @Override
  public T remove(Object key) {
    return removeAll(key.toString()).stream().findFirst().orElse(null);
  }

  public List<T> removeAll(String key) {
    if (key == null) {
      throw new NullPointerException();
    }
    return values.removeAll(key);
  }

  @Override
  @SuppressWarnings("java:S4968")
  public void putAll(Map<? extends String, ? extends T> m) {
    for (Entry<? extends String, ? extends T> entry : m.entrySet()) {
      put(entry.getKey(), entry.getValue());
    }
  }

  @Override
  public void clear() {
    values.clear();
  }

  @Override
  public @NonNull Set<String> keySet() {
    return values.keySet();
  }

  /**
   * @deprecated Use {@link #entries()} or {@link #stream()} instead.
   */
  @Override
  @Deprecated(forRemoval = true)
  public @NonNull List<T> values() {
    throw new UnsupportedOperationException(
        "This method is not supported as it would not respect the order of the entries");
  }

  /**
   * @deprecated Use {@link #entries()} or {@link #stream()} instead.
   */
  @Override
  @Deprecated(forRemoval = true)
  public @NonNull Set<Entry<String, T>> entrySet() {
    throw new UnsupportedOperationException(
        "This method is not supported as it would not respect the order of the entries");
  }

  /**
   * A snapshot of the entries, in insertion order: an immutable list, detached from the map, so
   * later puts and removals do not show up in it.
   *
   * <p>The {@link Entry} objects in it are the map's own rather than copies, so do not call {@code
   * setValue} on one - the list is detached, the entries are not.
   */
  public List<Entry<String, T>> entries() {
    // copyOf rather than stream().toList(): this is the hot path - stream(), equals and hashCode
    // all come through here - and copyOf measures ~1.4x quicker, being a toArray and a wrap
    // against a spliterator and a pipeline. It is only usable because the elements are the Entry
    // objects, which are never null; copyOf rejects null elements. See getAll.
    return List.copyOf(values.entries());
  }

  /**
   * Streams a snapshot of the entries.
   *
   * <p>The copy is tempting to drop in favour of streaming {@code values.entries()} directly.
   * Don't: converters add children to a node while walking it, and a live view turns that into a
   * {@link java.util.ConcurrentModificationException} - RbelContentTreeConverter does exactly this.
   */
  public Stream<Entry<String, T>> stream() {
    return entries().stream();
  }

  public RbelMultiMap<T> with(String key, T value) {
    put(key, value);
    return this;
  }

  public RbelMultiMap<T> withSkipIfNull(String key, T value) {
    if (value != null) {
      put(key, value);
    }
    return this;
  }

  /**
   * Returns a live iterator over the backing store. Supports {@link Iterator#remove()}. Not
   * thread-safe: a caller that needs concurrent access has to hold its own lock across the entire
   * iteration loop.
   */
  public Iterator<Entry<String, T>> iterator() {
    return values.entries().iterator();
  }

  public void putIfNotNull(String key, T value) {
    if (value != null) {
      put(key, value);
    }
  }

  @Override
  public String toString() {
    return values.toString();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof RbelMultiMap<?> otherMap)) {
      return false;
    }
    return entries().equals(otherMap.entries());
  }

  @Override
  public int hashCode() {
    return entries().hashCode();
  }
}
