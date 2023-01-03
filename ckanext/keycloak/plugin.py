import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from ckanext.keycloak.views import get_blueprint
from ckanext.keycloak.keycloak import get_keycloak_client, get_auth_url, get_keycloak_admin


server_url = toolkit.config.get('ckan.sso.keycloak_url', None)
client_id = toolkit.config.get('ckan.sso.keycloak_client_id', None)
realm_name = toolkit.config.get('ckan.sso.keycloak_realm', 'sprout')
redirect_uri = toolkit.config.get('ckan.sso.redirect_uri', None)
client_secret = toolkit.config.get('ckan.sso.keycloak_client_secret', None)

class KeycloakPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('assets', 'keycloak')

    # IAuthenticator
    def identify(self):
        pass

    def login(self):
        pass
        # admin = get_keycloak_admin(server_url, client_id, realm_name, client_secret)


    def get_blueprint(self):
        return get_blueprint()