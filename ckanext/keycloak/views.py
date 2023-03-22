# 

import logging
from flask import Blueprint, session
from ckan.plugins import toolkit as tk
import ckan.lib.helpers as h
import ckan.model as model
from ckan.common import g
from ckan.views.user import set_repoze_user, RequestResetView
from ckanext.keycloak.keycloak import KeycloakClient
import ckanext.keycloak.helpers as helpers
from urllib.parse import urlencode
import ckan.lib.dictization as dictization

log = logging.getLogger(__name__)
keycloak = Blueprint('keycloak', __name__, url_prefix='/user')
server_url = "https://auth.sproutopencontent.com/"
client_id = 'sprout-client'
realm_name = 'sprout'
redirect_uri = 'http://localhost:5000/user/sso_login'
client_secret_key = 'Y3Sn2ilmQWP9zaS8SwNqbKbVE6Q9yUIu'

client = KeycloakClient(server_url, client_id, realm_name, client_secret_key)

def _create_user(user_dict):
    context = {
        u'ignore_auth': True,
    }
    try:
        return tk.get_action(u'user_create')(context, user_dict)
    except tk.ValidationError as e:
        error_message = (e.error_summary or e.message or e.error_dict)
        tk.abort(400, error_message)

def _log_user_into_ckan(resp):
    """ Log the user into different CKAN versions.
    CKAN 2.10 introduces flask-login and login_user method.
    CKAN 2.9.6 added a security change and identifies the user
    with the internal id plus a serial autoincrement (currently static).
    CKAN <= 2.9.5 identifies the user only using the internal id.
    """
    if tk.check_ckan_version(min_version="2.10"):
        from ckan.common import login_user
        login_user(g.userobj)
        return

    if tk.check_ckan_version(min_version="2.9.6"):
        user_id = "{},1".format(g.userobj.id)
    else:
        user_id = g.userobj['name']
    set_repoze_user(user_id, resp)

    log.info(u'User {0}<{1}> logged in successfully'.format(g.userobj['name'], g.userobj['email']))

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
    userinfo = client.get_user_info(token)
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
        context = {"model": model, "session": model.Session}
        user = helpers.process_user(user_dict)
        g.user = user
        g.userobj = user
        context['user'] = user
        context['auth_user_obj'] = g.userobj
        user_id = "{}".format(user.get('name'))

        response = tk.redirect_to(tk.url_for('user.me',context))

        _log_user_into_ckan(response)
        log.info("Logged in success")
        return response
    else:
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
        h.flash_error('Invalid email address')
        return tk.redirect_to(tk.url_for('user.login'))
    return RequestResetView().post()

keycloak.add_url_rule('/sso', view_func=sso)
keycloak.add_url_rule('/sso_login', view_func=sso_login)
keycloak.add_url_rule('/reset_password', view_func=reset_password, methods=['POST'])

def get_blueprint():
    return keycloak