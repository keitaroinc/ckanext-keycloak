import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging
log = logging.getLogger(__name__)
from ckanext.keycloak.views import get_blueprint
# from ckan.common import g

class KeycloakPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    # plugins.implements(plugins.IAuthenticator)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('assets', 'keycloak')


    def get_blueprint(self):
        return get_blueprint()

    # def identify(self):
    #     # log.info("PLUGIN-IDENTIFY")
    #     user_ckan = toolkit.current_user.name
    #
    #     log.info(f"Plugin Retrieved username to G: {toolkit.g} {toolkit.g.get('user')}")
    #
    #     if user_ckan:
    #         log.info(f"Logged in user: {user_ckan}")
    #         toolkit.g.user = toolkit.current_user
    #     else:
    #         log.info(f"Logged out")
    #         # return toolkit.abort(400)
    #         # return toolkit.redirect_to('/sso_help')
    #
    # def login(self):
    #     # log.info("PLUGIN-LOGIN")
    #     pass
    #
    # def logout(self):
    #     log.info("PLUGIN-LOGOUT")
    #     pass
    #
    # def authenticate(self):
    #     log.info("PLUGIN-AUTHENTICATE")
    #     pass