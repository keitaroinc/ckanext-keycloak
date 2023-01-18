import logging

from flask import Blueprint, session

from ckan.plugins import toolkit as tk
import ckan.lib.helpers as h
import ckan.model as model
from ckan.common import g
from ckan.views.user import set_repoze_user, RequestResetView

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
            'plugin_extras': {
                'idp': 'google'
            }
        }
        user = helpers.process_user(user_dict)
        g.userobj = model.User.get(user['name'])
        g.user = user
        user_id = "{},1".format(user.get('id'))
        response = tk.redirect_to(tk.url_for('dashboard.index'))
        set_repoze_user(user_id, response)
       
        log.info(u'User {0}<{1}> logged in successfully'.format(g.userobj.name, g.userobj.email))
        return response
    return tk.redirect_to(tk.url_for('user.login'))

def reset_password():
    email = tk.request.form.get('user', None)

    if '@' not in email:
        log.info(f'User requested reset link for invalid email: {email}')
        h.flash_error('Invalid email address')
        return tk.redirect_to(tk.url_for('user.request_reset'))

    user = model.User.by_email(email)   

    if not user:
        log.info(u'User requested reset link for unknown user: {}'.format(email))
        return tk.redirect_to(tk.url_for('user.login'))
    user_extras = user[0].plugin_extras
    if user_extras and user_extras.get('idp', None) == 'google':
        log.info(u'User requested reset link for google user: {}'.format(email))
        return tk.abort(400, "Cannot reset password for corporate email authentication")
    return RequestResetView().post()


keycloak.add_url_rule('/sso', view_func=sso)
keycloak.add_url_rule('/sso_login', view_func=sso_login)
keycloak.add_url_rule('/reset_password', view_func=reset_password, methods=['POST'])

def get_blueprint():
    return keycloak