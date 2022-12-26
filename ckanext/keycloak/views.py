import logging

from flask import Blueprint, session
from ckan.plugins import toolkit as tk
from ckanext.keycloak.keycloak import get_keycloak_client, get_auth_url

log = logging.getLogger(__name__)

keycloak = Blueprint('keycloak', __name__, url_prefix='/user')


def sso():
    log.info("SSO Login")
    server_url = tk.config.get('ckan.sso.keycloak_url', None)
    client_id = tk.config.get('ckan.sso.client_id', None)
    realm_name = tk.config.get('ckan.sso.realm', 'sprout-realm')
    redirect_uri = tk.config.get('ckan.sso.redirect_uri', None)

    client = get_keycloak_client(server_url, client_id, realm_name)
    auth_url = get_auth_url(client=client, redirect_uri=redirect_uri)
    # Not sure why it's returning None, but this fixes it
    auth_url = auth_url.replace('None', 'ckan')
    return tk.redirect_to(auth_url)


def sso_login():
    breakpoint()
    data = tk.request.args


keycloak.add_url_rule('/sso', view_func=sso)
keycloak.add_url_rule('/sso_login', view_func=sso_login)

def get_blueprint():
    return keycloak