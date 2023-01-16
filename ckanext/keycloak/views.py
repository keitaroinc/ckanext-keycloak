import logging

from flask import Blueprint, session

from ckan.plugins import toolkit as tk
import ckan.model as model
from ckan.common import g
from ckan.views.user import set_repoze_user

from ckanext.keycloak.keycloak import KeycloakClient
import ckanext.keycloak.helpers as helpers

log = logging.getLogger(__name__)

keycloak = Blueprint('keycloak', __name__, url_prefix='/user')


server_url = tk.config.get('ckan.sso.keycloak_url', None)
client_id = tk.config.get('ckan.sso.keycloak_client_id', None)
realm_name = tk.config.get('ckan.sso.keycloak_realm', 'sprout')
redirect_uri = tk.config.get('ckan.sso.redirect_uri', None)
client_secret = tk.config.get('ckan.sso.keycloak_client_secret', None)
client = KeycloakClient(server_url, client_id, realm_name, client_secret)


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
    auth_url = None
    try:
        auth_url = client.get_auth_url(redirect_uri=redirect_uri)
    except Exception as e:
        log.error("Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))

    return tk.redirect_to(auth_url)


def sso_login():
    data = tk.request.args
    token = client.get_token(data['code'], redirect_uri)
    userinfo = client.get_user_info(token.get('access_token'))

    log.info("SSO Login: {}".format(userinfo))
    if userinfo:
        user_dict = {
            'name': helpers.ensure_unique_username_from_email(userinfo['preferred_username']),
            'email': userinfo['email'],
            'password': helpers.generate_password(),
            'fullname': userinfo['name'],
        }
        user = helpers.process_user(user_dict)
        g.userobj = model.User.get(user['name'])
        g.user = user
        response = tk.redirect_to(tk.url_for('dashboard.index'))
        set_repoze_user(user.get('name'), response)
       
        log.info(u'User {0}<{1}> logged in successfully'.format(g.userobj.name, g.userobj.email))
        return response
    return tk.redirect_to(tk.url_for('user.login'))


keycloak.add_url_rule('/sso', view_func=sso)
keycloak.add_url_rule('/sso_login', view_func=sso_login)

def get_blueprint():
    return keycloak