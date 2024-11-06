import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from ckanext.keycloak.views import get_blueprint
from ckanext.keycloak import helpers as h
import ckan.lib.helpers as helpers1

from os import environ
from urllib.parse import quote

from ckan.common import (
    _, config, g, request, current_user, login_user, logout_user, session,
    repr_untrusted
)


class KeycloakPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('assets', 'keycloak')

    def get_blueprint(self):
        return get_blueprint()
  
    # ITemplateHelpers

    def get_helpers(self):
        return {
            'button_style': h.button_style,
            'enable_internal_login': h.enable_internal_login,
        }
    
    # IAuthenticator

    def logout(self):

        server_url = toolkit.config.get('ckanext.keycloak.server_url', environ.get('CKANEXT__KEYCLOAK__SERVER_URL'))
        client_id = toolkit.config.get('ckanext.keycloak.client_id', environ.get('CKANEXT__KEYCLOAK__CLIENT_ID'))
        realm_name = toolkit.config.get('ckanext.keycloak.realm_name', environ.get('CKANEXT__KEYCLOAK__REALM_NAME'))
        
        redirect_url = helpers1.url_for(u"home.index", _external=True)
        encoded_redirect_url = quote(redirect_url, safe='')

        return toolkit.redirect_to(f"{server_url}/auth/realms/{realm_name}/protocol/openid-connect/logout?post_logout_redirect_uri={encoded_redirect_url}&client_id={client_id}")
