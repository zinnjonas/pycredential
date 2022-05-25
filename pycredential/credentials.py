import base64
from getpass import getpass

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

ENCODING = "utf-8"


class Credentials:
    """Class to load and store credentials

    The credentials will be encrypted and decrypted with the EAX method of the cryptodome module.
    """

    def __init__(self):
        self.__key = None
        self.__cipher = None

    @property
    def key(self):
        return self.__key

    @key.setter
    def key(self, new_key):
        self.__key = new_key
        self.__cipher = AES.new(self.__key, AES.MODE_EAX)

    def load_key(self, file):
        """Load a key from a file

        Load a key from a given file into the class. Initialise the cipher class

        Args:
            file (str): the file to load the key from
        """
        with open(file, "r") as key_file:
            self.__key = base64.urlsafe_b64decode(key_file.read())
        self.__cipher = AES.new(self.__key, AES.MODE_EAX)

    def store_key(self, file):
        """Store the key to a file

        In case there is currently no key in the credential class. A new 128-bit key will be generated

        Args:
            file (str): the file to store the key to
        """
        if self.__key is None:
            self.generate_key()
        with open(file, "w") as key_file:
            key_file.write(str(base64.urlsafe_b64encode(self.__key), ENCODING))

    def generate_key(self, key_length=None):
        """Generate a new key inside the class

        Generate a key and initialize the cipher class. If no 'key_length' is given 128 bit will be used.

        Args:
            key_length (int or None): the key_length. If None 128 bit will be used.
        """
        if not key_length:
            key_length = 16
        self.__key = get_random_bytes(key_length)
        self.__cipher = AES.new(self.__key, AES.MODE_EAX)

    def ask_and_store(self, file, key_file=None):
        """Ask the user for his credentials and store them

        This method will ask the user for a username and password. After data is given it will be stored to 'file'
        If no key exists during the call of the function a 128-bit key will be generated.

        Args:
            file (str): the file to store the credentials to
            key_file (str or None): the key file to store the key to. If None the key will not be stored
        """
        username = input("Username: ")
        password = getpass()
        self.store_user_data(file, username, password, key_file=key_file)
        del username
        del password

    def store_user_data(self, file, username, password, key_file=None):
        """Store given credentials encrypted into a file.

        This method will store the data encrypted into a file. If no key exist during the call of the function
        a 128-bit key will be generated. If 'key_file' is provided the key will be stored into that file.

        Args:
            file (str): the file to store the credentials into
            username (str): the username to store
            password (str): the password to store
            key_file (str or None): the file to store the key into
        """
        if self.__key is None:
            self.generate_key()
        if key_file is not None:
            self.store_key(key_file)
        password_encrypt, tag = self.__cipher.encrypt_and_digest(password.encode('utf-8'))
        password_string = str(base64.urlsafe_b64encode(password_encrypt), ENCODING)
        with open(file, "w") as credential_file:
            credential_file.write(f"Username={username}\n")
            credential_file.write(f"Password={password_string}\n")
            credential_file.write(str(base64.urlsafe_b64encode(self.__cipher.nonce), ENCODING) + '\n')
            credential_file.write(str(base64.urlsafe_b64encode(tag), ENCODING) + '\n')

    def load_user_data(self, file, key=None, key_file=None):
        """Load and decrypt credentials from a file

        This will load the credentials from 'file' and encrypt it with a given key.

        Args:
            file (str): the file to read the credentials from
            key (byte or None): the key to decrypt the credentials. If None the previous loaded key is used
            key_file (str or None): the key file to load a key from. If None the previous loaded key is used
        Returns:
            (str, str): the username and the password
        Raises:
            AttributeError: In case a key and a key_file is provided
        """
        if key is not None and key_file is not None:
            raise AttributeError("Either a key or key file needs to be given")
        if key_file:
            self.load_key(key_file)
        if key:
            self.__key = key
        with open(file, "r") as credential_file:
            username = credential_file.readline().split('=', 1)[1][:-1]
            password_cipher = base64.urlsafe_b64decode(credential_file.readline().split('=', 1)[1][:-1])
            nonce = base64.urlsafe_b64decode(credential_file.readline()[:-1])
            tag = base64.urlsafe_b64decode(credential_file.readline()[:-1])
        decipher = AES.new(self.__key, AES.MODE_EAX, nonce)
        return username, decipher.decrypt_and_verify(password_cipher, tag).decode(ENCODING)
