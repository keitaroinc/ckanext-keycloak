import logging
from keycloak import KeycloakOpenID

log = logging.getLogger(__name__)


def get_keycloak_client(server_url, client_id, realm_name):
    return KeycloakOpenID(
        server_url=server_url, client_id=client_id, realm_name=realm_name
    )

def get_auth_url(client, redirect_uri):
    return client.auth_url(redirect_uri=redirect_uri)

def get_user_info(client, token):
    return client.userinfo(token)


def get_user_groups(client, token):
    return client.userinfo(token).get('groups', [])
