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
package io.cucumber.core.plugin;

import static io.cucumber.junit.platform.engine.Constants.EXECUTION_DRY_RUN_PROPERTY_NAME;
import static io.cucumber.junit.platform.engine.Constants.FILTER_NAME_PROPERTY_NAME;
import static io.cucumber.junit.platform.engine.Constants.FILTER_TAGS_PROPERTY_NAME;

import io.cucumber.core.feature.FeatureParser;
import io.cucumber.core.gherkin.Feature;
import io.cucumber.core.gherkin.Pickle;
import io.cucumber.core.resource.ResourceScanner;
import io.cucumber.tagexpressions.TagExpressionParser;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import org.junit.platform.commons.support.AnnotationSupport;
import org.junit.platform.engine.ConfigurationParameters;
import org.junit.platform.engine.UniqueId;
import org.junit.platform.engine.support.descriptor.ClassSource;
import org.junit.platform.engine.support.descriptor.ClasspathResourceSource;
import org.junit.platform.engine.support.descriptor.FileSource;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.suite.api.ConfigurationParameter;
import org.junit.platform.suite.api.ConfigurationParametersResource;
import org.junit.platform.suite.api.DisableParentConfigurationParameters;

/**
 * Uses JUnit's suite configuration precedence and Cucumber's tag expressions and Gherkin parser.
 */
final class TigerScenarioSelection implements Predicate<TestIdentifier> {
  private final TestPlan plan;
  private final Map<UniqueId, ConfigurationParameters> configurations = new HashMap<>();
  private final Map<ConfigurationParameters, Predicate<TestIdentifier>> filters = new HashMap<>();
  private final Map<URI, List<Feature>> features = new HashMap<>();

  TigerScenarioSelection(TestPlan plan) {
    this.plan = plan;
  }

  @Override
  public boolean test(TestIdentifier test) {
    return filters.computeIfAbsent(configuration(test), this::filter).test(test);
  }

  private ConfigurationParameters configuration(TestIdentifier test) {
    var id = test.getUniqueIdObject();
    if (configurations.containsKey(id)) {
      return configurations.get(id);
    }
    var config =
        plan.getParent(test).map(this::configuration).orElse(plan.getConfigurationParameters());
    if (id.getLastSegment().getType().equals("suite")
        && test.getSource().orElse(null) instanceof ClassSource source) {
      // Use the same public request builder and annotation lookup as JUnit's suite engine.
      var suite = source.getJavaClass();
      var builder =
          LauncherDiscoveryRequestBuilder.request().enableImplicitConfigurationParameters(false);
      if (AnnotationSupport.findAnnotation(suite, DisableParentConfigurationParameters.class)
          .isEmpty()) {
        builder.parentConfigurationParameters(config);
      }
      AnnotationSupport.findRepeatableAnnotations(suite, ConfigurationParameter.class)
          .forEach(parameter -> builder.configurationParameter(parameter.key(), parameter.value()));
      AnnotationSupport.findRepeatableAnnotations(suite, ConfigurationParametersResource.class)
          .forEach(resource -> builder.configurationParametersResources(resource.value()));
      config = builder.build().getConfigurationParameters();
    }
    configurations.put(id, config);
    return config;
  }

  private Predicate<TestIdentifier> filter(ConfigurationParameters config) {
    if (config.getBoolean(EXECUTION_DRY_RUN_PROPERTY_NAME).orElse(false)) {
      return test -> false;
    }
    var tags = config.get(FILTER_TAGS_PROPERTY_NAME).map(TagExpressionParser::parse);
    var name = config.get(FILTER_NAME_PROPERTY_NAME).map(Pattern::compile);
    if (tags.isEmpty() && name.isEmpty()) {
      return test -> true;
    }
    return test -> {
      var pickle = pickle(test);
      return tags.map(expression -> expression.evaluate(pickle.getTags())).orElse(true)
          && name.map(pattern -> pattern.matcher(pickle.getName()).matches()).orElse(true);
    };
  }

  private Pickle pickle(TestIdentifier test) {
    URI uri;
    int line;
    var source = test.getSource().orElseThrow();
    if (source instanceof FileSource file) {
      uri = file.getUri();
      line = file.getPosition().orElseThrow().getLine();
    } else if (source instanceof ClasspathResourceSource resource) {
      uri = URI.create("classpath:" + resource.getClasspathResourceName());
      line = resource.getPosition().orElseThrow().getLine();
    } else {
      throw new IllegalArgumentException("Unsupported Cucumber scenario source: " + source);
    }
    // Display names can include feature prefixes or example numbers. Match the actual pickle name.
    return features
        .computeIfAbsent(
            uri,
            location ->
                new ResourceScanner<>(
                        () -> Thread.currentThread().getContextClassLoader(),
                        path -> true,
                        new FeatureParser(UUID::randomUUID)::parseResource)
                    .scanForResourcesUri(location))
        .stream()
        .flatMap(feature -> feature.getPickles().stream())
        .filter(pickle -> pickle.getLocation().getLine() == line)
        .findFirst()
        .orElseThrow();
  }
}
