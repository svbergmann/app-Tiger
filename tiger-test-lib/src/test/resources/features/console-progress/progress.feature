@feature
Feature: Console progress
  @single
  Scenario: one
    Given a progress scenario

  Scenario Outline: variants <n>
    Given a progress scenario
    Examples:
      | n |
      | 1 |
      | 2 |
