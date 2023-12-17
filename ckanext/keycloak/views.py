import logging
from flask import Blueprint
from ckan.plugins import toolkit as tk
import ckan.lib.helpers as h
import ckan.model as model
from ckan.views.user import set_repoze_user, RequestResetView
from ckanext.keycloak.keycloak import KeycloakClient
import ckanext.keycloak.helpers as helpers
from os import environ

log = logging.getLogger(__name__)

keycloak = Blueprint('keycloak', __name__, url_prefix='/user')

server_url = tk.config.get('ckanext.keycloak.server_url', environ.get('CKANEXT__KEYCLOAK__SERVER_URL'))
client_id = tk.config.get('ckanext.keycloak.client_id', environ.get('CKANEXT__KEYCLOAK__CLIENT_ID'))
realm_name = tk.config.get('ckanext.keycloak.realm_name', environ.get('CKANEXT__KEYCLOAK__REALM_NAME'))
redirect_uri = tk.config.get('ckanext.keycloak.redirect_uri', environ.get('CKANEXT__KEYCLOAK__REDIRECT_URI'))
client_secret_key = tk.config.get('ckanext.keycloak.client_secret_key',
                                  environ.get('CKANEXT__KEYCLOAK__CLIENT_SECRET_KEY'))

client = KeycloakClient(server_url, client_id, realm_name, client_secret_key)


def _log_user_into_ckan(resp):
    """ Log the user into different CKAN versions.
    CKAN 2.10 introduces flask-login and login_user method.
    CKAN 2.9.6 added a security change and identifies the user
    with the internal id plus a serial autoincrement (currently static).
    CKAN <= 2.9.5 identifies the user only using the internal id.
    """
    # log.info("_log_user_into_ckan()")
    if tk.check_ckan_version(min_version="2.10"):
        from ckan.common import login_user
        login_user(tk.g.user_obj)
        return

    if tk.check_ckan_version(min_version="2.9.6"):
        user_id = "{},1".format(g.user_obj.id)
    else:
        user_id = tk.g.user
    set_repoze_user(user_id, resp)

    log.info(u'User {0}<{1}> logged in successfully'.format(g.user_obj.name, g.user_obj.email))


def sso():
    # log.info("sso()")
    data = tk.request.args
    # log.info(f"sso data: {data}")
    auth_url = None
    try:
        auth_url = client.get_auth_url(redirect_uri=redirect_uri)
    except Exception as e:
        log.error("Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    return tk.redirect_to(auth_url)


def sso_login():
    # log.info("sso_login()")
    data = tk.request.args
    # log.info(f"sso_login data: {data}")
    token = client.get_token(data['code'], redirect_uri)
    userinfo = client.get_user_info(token)
    usergroups = client.get_user_groups(token)
    log.info("User Info: {}".format(userinfo))
    log.info("User Groups: {}".format(usergroups))

    is_user_ckan_admin = 'ckan_admin' in usergroups

    if userinfo and is_user_ckan_admin:  # only log in if admin
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
        tk.g.user_obj = helpers.process_user(user_dict)
        tk.g.user = tk.g.user_obj.name
        context['user'] = tk.g.user
        context['auth_user_obj'] = tk.g.user_obj

        response = tk.redirect_to(tk.url_for('user.me', context))

        _log_user_into_ckan(response)
        log.info("Logged in success")
        return response
    elif userinfo and not is_user_ckan_admin:  # if user exists but not admin

        # h.flash_error(f'User {userinfo["preferred_username"]} doesn\'t have permission to log in')
        return tk.redirect_to(tk.url_for('organization.index'))
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

# This endpoint will take care of auto-login
def sso_autologin():
    # log.info("sso_autologin()")
    data = tk.request.args
    # log.info(f"sso data: {data}")

    if len(data):

        if data.get('code'):
            # log.info(data.get('code'))
            # log.info(f"There is code!!!")
            return tk.redirect_to('keycloak.sso')  # complete login/create user
        elif data.get('error'):
            # log.info(f"There is no code!!!")
            return tk.redirect_to('organization.index')  # redirect to organizations page
    else:
        # check keycloak for logged in state
        try:
            auth_url = client.get_auth_url(redirect_uri=f"{environ.get('CKAN_SITE_URL')}/user/sso_autologin")
        except Exception as e:
            log.error("Error getting auth url: {}".format(e))
            return tk.abort(500, "Error getting auth url: {}".format(e))
        return tk.redirect_to(auth_url + '&prompt=none')  # &prompt=none is for skipping the UI of keycloak


# Enable this for autologin
@keycloak.before_app_request
def before_app_request():
    # log.info("keycloak.before_app_request")
    # log.info(f"Endpoint: {tk.request.endpoint}")

    # if already logged in
    user_ckan = tk.current_user.name
    if user_ckan:
        pass

    # if not logged in, check if keycloak has cookie already
    else:
        if tk.request.endpoint == 'home.index':
            return tk.redirect_to('keycloak.sso_autologin')


keycloak.add_url_rule('/sso', view_func=sso)
keycloak.add_url_rule('/sso_autologin', view_func=sso_autologin)
keycloak.add_url_rule('/sso_login', view_func=sso_login)
keycloak.add_url_rule('/reset_password', view_func=reset_password, methods=['POST'])


def get_blueprint():
    return keycloak
