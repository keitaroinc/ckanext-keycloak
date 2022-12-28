import logging

from flask import Blueprint, session
from ckan.plugins import toolkit as tk
from ckanext.keycloak.keycloak import get_keycloak_client, get_auth_url

log = logging.getLogger(__name__)

keycloak = Blueprint('keycloak', __name__, url_prefix='/user')


def _create_user(user_dict):
    context = {
        u'ignore_auth': True,
    }

    try:
        return tk.get_action(u'user_create')(context, user_dict)
    except tk.ValidationError as e:
        error_message = (e.error_summary or e.message or e.error_dict)
        tk.abort(400, error_message)

def sso():
    log.info("SSO Login")
    server_url = tk.config.get('ckan.sso.keycloak_url', None)
    client_id = tk.config.get('ckan.sso.keycloak_client_id', None)
    realm_name = tk.config.get('ckan.sso.keycloak_realm', 'sprout')
    redirect_uri = tk.config.get('ckan.sso.redirect_uri', None)
    
    client = None
    auth_url = None
    try:
        client = get_keycloak_client(server_url, client_id, realm_name)
    except Exception as e:
        log.error("Error getting keycloak client: {}".format(e))
        return tk.abort(500, "Error getting keycloak client: {}".format(e))

    try:
        auth_url = get_auth_url(client=client, redirect_uri=redirect_uri)
    except Exception as e:
        log.error("Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    # Not sure why it's returning None, but this fixes it
    # auth_url = auth_url.replace('None', 'sprout-client')
    return tk.redirect_to(auth_url)


def sso_login():
    data = tk.request.args
    log.info("SSO Login: {}".format(data))
    if 'user' in data:
        user = data['user']
        user_dict = {
            'name': data['user'],
            'email': data['email'],
            'password': _genreate_password(),
            'fullname': data['fullname'],
        }
        _create_user(user_dict)
        session['ckanext-keycloak-user'] = user
        session.save()
        return tk.redirect_to('/')


keycloak.add_url_rule('/sso', view_func=sso)
keycloak.add_url_rule('/sso_login', view_func=sso_login)

def get_blueprint():
    return keycloak