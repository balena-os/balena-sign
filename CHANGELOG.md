Change log
-----------

# v0.1.0
## (2022-12-09)

# v1.5.5
## (2025-04-15)

* Update balena/cert-manager Docker tag to v0.3.3 [balena-renovate[bot]]

# v1.5.4
## (2025-04-12)

* Fix package rules in renovate config. [Carlo Miguel F. Cruz]

# v1.5.3
## (2025-04-11)

* patch: explicitly allow docker image updates by renovate. [Carlo Miguel F. Cruz]

# v1.5.2
## (2025-04-10)

* patch: Use the default env. var. set by Supervisor [Anton Belodedenko]

# v1.5.1
## (2025-04-10)

* patch: Fix Renovate config [Anton Belodedenko]

# v1.5.0
## (2025-02-17)

* cst: update submodule to version 0.0.3 [Alex Gonzalez]
* requirements: update to patch known vulnerabilities [Alex Gonzalez]
* Dockerfile: update to cst 4.0.0 and Python 3.12.9 [Alex Gonzalez]
* imx: Fix linter warnings [Alex Gonzalez]
* imx: sort the certificate list [Alex Gonzalez]

# v1.4.2
## (2025-02-10)

* Check balena-sign health before pinging external HC hook. [Carlo Miguel F. Cruz]

# v1.4.1
## (2025-01-07)

* deploy to balenaCloud with Flowzone [Anton Belodedenko]

# v1.4.0
## (2024-12-10)

* Add support for signing SHA256 digests using an existing certificate [Michal Toman]

# v1.3.1
## (2024-12-04)

* README: improve bootstrap example [Joseph Kogut]

# v1.3.0
## (2024-10-28)

* Add a metrics agent for collecting worker resource metrics. [Carlo Miguel F. Cruz]

# v1.2.1
## (2024-10-25)

* Fix typos [Anton Belodedenko]

# v1.2.0
## (2024-10-25)

* Add capability to send logs to Loki [Anton Belodedenko]

# v1.1.0
## (2024-10-23)

* README: update bootstrapping example [Alex Gonzalez]
* rsa: Return an empty list when no keys are present [Alex Gonzalez]
* secureboot: extend the capped size for EFI image signing [Alex Gonzalez]
* Use python 3.12 and update dependencies [Alex Gonzalez]
* Dockerfile: build NXP's CST tool [Alex Gonzalez]

# v1.0.2
## (2024-07-04)

* rsa: improve handling of temporary files [Alex Gonzalez]

# v1.0.1
## (2024-07-04)

* workflows: flowzone: fix linter errors [Alex Gonzalez]

# v1.0.0
## (2024-03-12)

* Add support for RPI signing [Alex Gonzalez]

# v0.3.5
## (2023-12-19)

* Remove repo config from flowzone.yml [Kyle Harding]

# v0.3.4
## (2023-10-16)

* Add Apache 2.0 LICENSE [Michal Toman]

# v0.3.3
## (2023-08-07)

* notify on HC failure [Anton Belodedenko]

# v0.3.2
## (2023-05-29)

* Extend renovate config from balena-io/renovate-config [Kyle Harding]

# v0.3.1
## (2023-04-05)

* Fix calls to _sign_esl for multiple certificates [Michal Toman]

# v0.3.0
## (2023-04-05)

* Allow to specify certificate expiry in the API and default to 20 years [Michal Toman]
* Allow signing multiple certificates for secure boot variables [Michal Toman]

# v0.2.7
## (2023-03-29)

* Allow signing for dbx [Michal Toman]

# v0.2.6
## (2023-03-29)

* Allow signing db for appending [Michal Toman]

# v0.2.5
## (2023-03-15)

* README: revert to using lower case for certificates names [Alex Gonzalez]

# v0.2.4
## (2023-03-14)

* compose: add logshipper service [Alex Gonzalez]

# v0.2.3
## (2023-03-09)

* README: update bootstrap example to match with meta-balena defaults [Michal Toman]

# v0.2.2
## (2023-03-09)

* Allow signing external ESL at db level [Michal Toman]

# v0.2.1
## (2023-03-08)

* bootstrap: do not self-sign KEK, sign by PK instead [Michal Toman]

# v0.2.0
## (2023-03-07)

* flowzone: don't try to publish [Alex Gonzalez]
* app: fix signing of kek and db certificates [Alex Gonzalez]
* Change import/export API from binary to JSON [Michal Toman]
* Added endpoints to export/import AES encrypted backups of vault [20k-ultra]
* Add example bootstrap command to README [Michal Toman]
* Extend bootstrap functionality [Michal Toman]
* Added `POST /bootstrap` to quickly setup all signing material needed [20k-ultra]
* Also provide certificates in DER format [Michal Toman]
* Allow chain-signing of secure boot variables [Michal Toman]
* Added a volume for secret storage to persist across updates [20k-ultra]
* Use correct variable when logging missing key_id [20k-ultra]
* Refactor project structure so the source is easier to find [20k-ultra]
* Move container source out of src folder This is to avoid confusion that this folder does not container the source for the balena-sign application [20k-ultra]
* Remove `BALENA_API_DOMAIN` config because it was broken Unable to quickly resolve so removing for now [20k-ultra]
* Add .gitignore for .venv This is so you can use virtual env to install the project dependencies so your editor's LSP can properly provide error checking [20k-ultra]
* Update dependency urllib3 to 1.26.14 [Renovate Bot]
* Add haproxy + AWS/EC2 specific [ab77]
* Update dependency uWSGI to 2.0.21 [Renovate Bot]
* Update dependency flask to 1.1.4 [Renovate Bot]
* Use balena-cloud authentication for HTTP security [20k-ultra]
* Default to SHA256 hashes in X.509 certificates [Michal Toman]
* Increase HTTP and socket timeouts [Michal Toman]
* Update to linux-kbuild-5.10 because previous version was not available [20k-ultra]

* Enable flowzone workflows [Michal Toman]
* Add repo.yml to enable versionbot [Michal Toman]
* Use subprocess.run instead of subprocess.call for executing commands [Michal Toman]
* Add endpoints for creating and fetching SSL certificates [Michal Toman]
* Add endpoint for creating GPG keys [Michal Toman]
* Remove redundant icon [Michal Toman]
* Add icon [Michal Toman]
* Initial commit [Michal Toman]
