import logging
import string
import re
import random
import secrets


import ckan.model as model
import ckan.plugins.toolkit as tk
from os import environ


log = logging.getLogger(__name__)


def generate_password():
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(8))


def ensure_unique_username_from_email(email):
    localpart = email.split('@')[0]
    cleaned_localpart = re.sub(r'[^\w]', '-', localpart).lower()

    if not model.User.get(cleaned_localpart):
        return cleaned_localpart

    max_name_creation_attempts = 10

    for _ in range(max_name_creation_attempts):
        random_number = random.SystemRandom().random() * 10000
        name = '%s-%d' % (cleaned_localpart, random_number)
        if not model.User.get(name):
            return name

    return cleaned_localpart


def process_user(userinfo):
    return _get_user_by_email(userinfo.get('email')) or _create_user(userinfo)


def _get_user_by_email(email):
    user = model.User.by_email(email)
    if user and isinstance(user, list):
        user = user[0]

    activate_user_if_deleted(user)
    
    return user


def activate_user_if_deleted(user):
    u'''Reactivates deleted user.'''
    if not user:
        return
    if user.is_deleted():
        user.activate()
        user.commit()
        log.info(u'User {} reactivated'.format(user.name))


def _create_user(userinfo):
    context = {
        u'ignore_auth': True,
    }
    created_user_dict = tk.get_action(
        u'user_create'
    )(context, userinfo)
    
    return _get_user_by_email(created_user_dict['email'])


def button_style():

    return tk.config.get('ckanext.keycloak.button_style',
                         environ.get('CKANEXT__KEYCLOAK__BUTTON_STYLE'))
