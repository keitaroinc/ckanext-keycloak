import pytest
import ckan.model as model
import ckan.tests.factories as factories
from ckanext.keycloak import helpers as h


def test_generate_password():
    password = h.generate_password()
    assert len(password) >= 8
    assert type(password) is str


@pytest.mark.usefixtures(u'clean_db', u'clean_index')
def test_activate_user_if_deleted():
    user = factories.User()
    user = model.User.get(user[u'name'])
    user.delete()
    h.activate_user_if_deleted(user)
    assert not user.is_deleted()


@pytest.mark.usefixtures(u'clean_db')
def test_ensure_unique_user_name_existing_user():

    user = factories.User(
        name='existing-user',
        email=u'existing-user@example.com'
    )

    user_name = h.ensure_unique_username_from_email(user['email'])

    assert user_name != user['email'].split('@')[0]
    assert user_name.startswith(user['email'].split('@')[0])