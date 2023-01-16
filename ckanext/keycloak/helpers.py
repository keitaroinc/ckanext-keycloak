import logging
import string
import re
import random
import secrets


import ckan.model as model
import ckan.plugins.toolkit as tk
import ckan.lib.dictization.model_dictize as model_dictize


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
    context = {
        u'ignore_auth': True,
    }
    return _get_user_by_email(userinfo.get('email')) or tk.get_action(
        u'user_create'
    )(context, userinfo)

def _get_user_by_email(email):
    context = {
        u'keep_email': True,
        u'model': model,
    }
    breakpoint()
    user = model.User.by_email(email)
    if user and isinstance(user, list):
        user = user[0]

    activate_user_if_deleted(user)

    return model_dictize.user_dictize(user, context) if user else False


def activate_user_if_deleted(user):
    u'''Reactivates deleted user.'''
    if not user:
        return
    if user.is_deleted():
        user.activate()
        user.commit()
        log.info(u'User {} reactivated'.format(user.name))
