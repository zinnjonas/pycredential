import base64
import os.path
from getpass import getpass

import pytest
import credentials

from pycredential.credentials import Credentials, ENCODING

SECRET_KEY = b"Hello Credential"
KEY_FILE = "secret.key"
USER_CRED = "user.cred"
USER = "user"
PASSWORD = "passwd"


def clear_files():
    if os.path.exists(USER_CRED):
        os.remove(USER_CRED)
    if os.path.exists(KEY_FILE):
        os.remove(KEY_FILE)


def setup():
    clear_files()


def teardown():
    clear_files()


def test_store_key():
    cred = Credentials()
    cred.key = SECRET_KEY
    cred.store_key(KEY_FILE)
    assert os.path.exists(KEY_FILE)
    with open(KEY_FILE, "r") as secret_file:
        content = secret_file.read()
    assert cred.key, base64.urlsafe_b64decode(content)


def test_load_key():
    cred = Credentials()
    with open(KEY_FILE, "w") as secret_file:
        secret_file.write(str(base64.urlsafe_b64encode(SECRET_KEY), ENCODING))
    cred.load_key(KEY_FILE)
    assert cred.key, SECRET_KEY


def test_store_load_key():
    cred = Credentials()
    cred2 = Credentials()
    cred.key = SECRET_KEY
    cred.store_key(KEY_FILE)
    cred2.load_key(KEY_FILE)
    assert cred.key, cred2.key


def test_generate_key():
    cred = Credentials()
    cred.generate_key()
    assert len(cred.key), 16
    cred.generate_key(32)
    assert len(cred.key), 32


def test_generate_invalid_key():
    with pytest.raises(ValueError):
        cred = Credentials()
        cred.generate_key(1)


def test_store_user_data():
    cred = Credentials()
    cred.key = SECRET_KEY
    cred.store_user_data(USER_CRED, USER, PASSWORD)
    assert os.path.exists(USER_CRED)


def test_load_user_data():
    cred = Credentials()
    cred.key = SECRET_KEY
    cred.store_user_data(USER_CRED, USER, PASSWORD)
    user, password = cred.load_user_data(USER_CRED)
    assert user, USER
    assert password, PASSWORD


def test_load_user_data_key_file():
    cred = Credentials()
    cred2 = Credentials()
    cred.key = SECRET_KEY
    cred.store_user_data(USER_CRED, USER, PASSWORD, key_file=KEY_FILE)
    user, password = cred2.load_user_data(USER_CRED, key_file=KEY_FILE)
    assert cred2.key, cred.key
    assert user, USER
    assert password, PASSWORD


def test_ask_and_store():
    def mock_input(_):
        return USER

    def mock_password():
        return PASSWORD

    cred = Credentials()
    cred2 = Credentials()
    cred.key = SECRET_KEY
    credentials.input = mock_input
    credentials.getpass = mock_password

    cred.ask_and_store(USER_CRED, key_file=KEY_FILE)
    user, password = cred2.load_user_data(USER_CRED, key_file=KEY_FILE)
    assert cred2.key, cred.key
    assert user, USER
    assert password, PASSWORD
    credentials.input = input
    credentials.getpass = getpass
