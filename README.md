[![Tests](https://github.com/keitaroinc/ckanext-keycloak/workflows/Tests/badge.svg?style=flat)](https://github.com/keitaroinc/ckanext-keycloak/actions/workflows/test.yml)

# ckanext-keycloak

ckanext-keycloak is an extension for CKAN, that adds Single Sign On options for CKAN portals. It enables the users to authenticate with [Keycloack](https://www.keycloak.org/) instead of creating a new user account on CKAN.

## Requirements

**Note**
This extension requires users to have set up a Keycloak server and have a client set up for CKAN. For more information on how to set up Keycloak, please refer to the [Keycloak documentation](https://www.keycloak.org/documentation.html).

For the development, the following requirements must be met:

* Create a realm in Keycloak
* Create a client in Keycloak
* Set the client's `Valid Redirect URIs` to `http://localhost:5000/user/sso_login`
* Configure identity providers in Keycloak (e.g. Google, GitHub, etc.)

If you want to use multiple identity providers, you need to set the `first_login_broker` as authentication workflow. This workflow will redirect the user to the login page of the identity provider. After the
user has logged in, the user will be logged in to CKAN.


## Compatibility

Compatibility with core CKAN versions:

| CKAN version    | Compatible?   |
| --------------- | ------------- |
| 2.9             | YES    |
| --------------- | ------------- |
| 2.10            | YES    |
| --------------- | ------------- |
| master            | YES    |
| --------------- | ------------- |


## Installation

To install ckanext-keycloak:

1. Activate your CKAN virtual environment, for example:
    ```
    . /usr/lib/ckan/default/bin/activate
    ```

2. Clone the source and install it on the virtualenv
    ```
    git clone https://github.com/kitaroinc/ckanext-keycloak.git
    cd ckanext-keycloak
    pip install -e .
	pip install -r requirements.txt
    ```
3. Add `keycloak` to the `ckan.plugins` setting in your CKAN
   config file (by default the config file is located at
   `/etc/ckan/default/ckan.ini`).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu:

     sudo service apache2 reload


## Config settings

Configuration settings to run the extension

    
    ckanext.keycloak.server_url = link_to_keycloack_authentication_url
    ckanext.keycloak.client_id = client_id
    ckanext.keycloak.realm_name = realm_name
    ckanext.keycloak.redirect_uri = redirect_url
    ckanext.keycloak.client_secret_key = client_secret_key
    ckanext.keycloak.button_style = google/azure (if empty it will have the default stile)
    ckanext.keycloak.enable_ckan_internal_login = True or False
    

## Developer installation

To install ckanext-keycloak for development, activate your CKAN virtualenv and
do:

    git clone https://github.com/keitaroinc/ckanext-keycloak.git
    cd ckanext-keycloak
    python setup.py develop
    pip install -r dev-requirements.txt


## Tests

To run the tests, do:

    pytest --ckan-ini=test.ini


## Releasing a new version of ckanext-keycloak

If ckanext-keycloak should be available on PyPI you can follow these steps to publish a new version:

1. Update the version number in the `setup.py` file. See [PEP 440](http://legacy.python.org/dev/peps/pep-0440/#public-version-identifiers) for how to choose version numbers.

2. Make sure you have the latest version of necessary packages:

    pip install --upgrade setuptools wheel twine

3. Create a source and binary distributions of the new version:

       python setup.py sdist bdist_wheel && twine check dist/*

   Fix any errors you get.

4. Upload the source distribution to PyPI:

       twine upload dist/*

5. Commit any outstanding changes:

       git commit -a
       git push

6. Tag the new release of the project on GitHub with the version number from
   the `setup.py` file. For example if the version number in `setup.py` is
   0.0.1 then do:

       git tag 0.0.1
       git push --tags

## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
# ckanext-keycloak
