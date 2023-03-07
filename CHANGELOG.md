Change log
-----------

# v0.1.0
## (2022-12-09)

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
