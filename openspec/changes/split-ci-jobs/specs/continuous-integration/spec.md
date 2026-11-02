# Spec Delta

## Purpose

States what the repository's continuous integration runs on every push and pull request, and how it reports. Each concern fails on its own, and one aggregate result is the status the repository's rules require.

## ADDED Requirements

### Requirement: Each check reports as its own job
Continuous integration SHALL run each check as a separate job with its own status:
- formatting;
- vet;
- lint;
- the generate check;
- the vulnerability check;
- tests;
- code scanning;
- spec validation.

A failing check SHALL fail its own job only, and every other job SHALL still run to completion and report its own result.

#### Scenario: Lint finding
- **WHEN** a pull request introduces a finding the configured linters report, and nothing else is wrong
- **THEN** the lint job fails, and the formatting, vet, generate, vulnerability, test, code-scanning and spec-validation jobs each pass

#### Scenario: Two checks fail
- **WHEN** a pull request leaves a Go file unformatted and breaks a test
- **THEN** both the formatting job and the test job fail, and each names its own cause in its own log

### Requirement: Only tests run against each database pairing
The test job SHALL run once for each PostgreSQL and Redis pairing CI tests against. Every other check SHALL run once per run, without a database. The test that must not run beside the rest of the suite SHALL run within each test job, after the suite.

#### Scenario: Two database pairings
- **WHEN** CI runs on a matrix with two PostgreSQL and Redis pairings
- **THEN** two test jobs run, one per pairing, and the formatting, vet, lint, generate, vulnerability, code-scanning and spec-validation jobs each run once

#### Scenario: Isolated test
- **WHEN** a test job runs
- **THEN** the isolated rate-limit prune test runs after the rest of that job's suite has finished, never beside it

### Requirement: One aggregate result
Continuous integration SHALL end with one aggregate job. It SHALL pass only when every other job in the run passed. It SHALL fail when any of them failed, was cancelled or was skipped, and SHALL never itself be skipped because another job failed. Its name SHALL NOT change when jobs are added, renamed or removed.

#### Scenario: One job fails
- **WHEN** the vulnerability job fails and every other job passes
- **THEN** the aggregate job runs and fails, rather than being skipped

#### Scenario: Every job passes
- **WHEN** every check job passes
- **THEN** the aggregate job passes

#### Scenario: Job added
- **WHEN** a new check job is added to the workflow
- **THEN** the aggregate job's result depends on it, and its name is unchanged

### Requirement: Draft pull requests run nothing
A pull request in draft SHALL run no CI job. Marking it ready for review SHALL run every job, and every later push to it SHALL run them again. A push to the main branch SHALL always run every job.

#### Scenario: Draft
- **WHEN** a draft pull request is opened or pushed to
- **THEN** no CI job runs

#### Scenario: Ready for review
- **WHEN** a draft pull request is marked ready for review
- **THEN** every CI job runs on its head commit

### Requirement: Code scanning analyses Go and workflows
Code scanning SHALL run CodeQL on every push to the main branch and on every pull request it runs for. It SHALL analyse the Go code of every workspace module and the repository's workflow files, and upload the results to the repository's code scanning. Languages outside these two SHALL NOT be analysed.

#### Scenario: Pull request analysed
- **WHEN** CI runs for a pull request
- **THEN** CodeQL results for Go and for the workflow files exist for the pull request's head commit

#### Scenario: Every workspace module analysed
- **WHEN** the Go analysis runs
- **THEN** it covers the packages of every module listed in the workspace, not only the root module

#### Scenario: Python is not analysed
- **WHEN** the repository contains Python files only as evidence in an archived change
- **THEN** no Python analysis runs and no Python results are uploaded

### Requirement: Spec validation checks settled specs and the changes a run touches
The spec-validation job SHALL validate:
- every settled spec;
- every archived change;
- every active change that has a file changed by the pushed commits or the pull request.

It SHALL fail on any validation error and name the item. It SHALL use non-strict validation, so warnings alone pass. An active change that no file in the run touches SHALL NOT be validated.

#### Scenario: Touched change is invalid
- **WHEN** a pull request edits a change whose delta leaves out a scenario that the settled spec has
- **THEN** the spec-validation job fails and names that change

#### Scenario: Untouched draft change
- **WHEN** a pull request leaves untouched an active change that has a proposal and no deltas yet
- **THEN** that change is not validated, and the job does not fail because of it

#### Scenario: Settled spec broken
- **WHEN** a pull request leaves a settled spec with a requirement that has no scenario
- **THEN** the spec-validation job fails and names the spec

#### Scenario: Warnings only
- **WHEN** the only findings are warnings, such as an over-long requirement
- **THEN** the spec-validation job passes

### Requirement: Spec validation runs locally on its own command
The spec validation CI runs SHALL also be runnable locally through one command. That command SHALL NOT be part of the build-gate command, so running the build gates SHALL need no toolchain beyond Go.

#### Scenario: Local spec validation
- **WHEN** a contributor with the OpenSpec CLI runs the spec-validation command on a checkout
- **THEN** it validates the settled specs, the archived changes and the active changes the working tree changes against the main branch, and fails exactly where CI's spec-validation job would

#### Scenario: Build gates without Node
- **WHEN** a contributor without Node or the OpenSpec CLI runs the build-gate command
- **THEN** it runs every build gate and does not fail for lack of either
