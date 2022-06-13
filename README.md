# github-actions-bazel

This project demonstrates SCA (Software Composition Analysis) scanning C/C++ code by the blackduck-c-cpp python script and its resulted review in the Github Actions frameworks.

## Input
Black Duck API Token: Provided from the Github Actions secrets

Black Duck URL: Provided in from Github Actions secrets

Project Name: Provided in the Github Actions YAML

Version Name: Provided by the build number by Github Actions

## Usage
Both Push & Pull Requests trigger the Github Actions. The scanned results are reviewed on the Black Duck Dashboard and the detected vulnerabilities are found in the Github Actions Security Dashboard too.