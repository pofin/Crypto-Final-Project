import json
import logging

from final.crypto import *


logger = logging.getLogger(__name__)


class ConfigHelper:
  """ Class for loading and configuring cryptosystems. """

  # Default size for nonces.
  _NONCE_SIZE = 32
  # Default key for the MAC.
  _MAC_DEFAULT_KEY = "mac_secret"

  def __init__(self):
    # Create the manager.
    self.__manager = crypto_manager.CryptoManager()

    # Create common nonce and MAC stuff.
    self.__nonce_gen = sequential_nonce.SequentialNonceGenerator( \
        self._NONCE_SIZE)
    self.__nonce_ver = sequential_nonce.SequentialNonceVerifier( \
        self._NONCE_SIZE)
    self.__mac = HMAC.HMAC(self._MAC_DEFAULT_KEY)

  def __load_config(self, config_file):
    """ Loads configuration data from a file.
    Args:
      config_file: The file to load from.
    Returns:
      Configuration dict. """
    logger.debug("Loading config from %s." % (config_file))

    conf_handle = open(config_file)
    conf_data = json.load(conf_handle)
    conf_handle.close()

    return conf_data

  def add_rc4(self, conf_file):
    """ Initializes the RC4 cipher.
    Args:
      conf_file: The JSON file to load configuration from. """
    # Load the configuration.
    config = self.__load_config(conf_file)
    key_size = config["key_size"]

    rc4 = RC4.RC4(key_size)
    rc4_con = secure_context.SymmetricContext(rc4, self.__nonce_gen,
                                              self.__nonce_ver, self.__mac)
    self.__manager.add_symmetric_context(rc4_con)

  def add_rsa(self, conf_file):
    """ Initializes RSA.
    Args:
      conf_file: The JSON file to load configuration from. """
    # Load the configuration.
    config = self.__load_config(conf_file)
    key_size = config["key_size"]
    pub_key = config["pub_key"]
    priv_key = config["priv_key"]

    rsa = RSA.RSA(key_size)
    rsa.set_key_pair(pub_key, priv_key)
    rsa_pub = secure_context.PublicKeyContext(rsa, self.__nonce_gen,
                                              self.__nonce_ver, self.__mac)
    rsa_priv = secure_context.PrivateKeyContext(rsa, self.__nonce_gen,
                                                self.__nonce_ver, self.__mac)

    self.__manager.add_pkc_contexts(rsa_pub, rsa_priv)

  def add_ssrsa(self, conf_file):
    """ Initializes SSRSA.
    Args:
      conf_file: The JSON file to load configuration from. """
    # Load the configuration.
    config = self.__load_config(conf_file)
    key_size = config["key_size"]
    pub_key = config["pub_key"]
    priv_key = config["priv_key"]

    ssrsa = SSRSA.SSRSA(key_size)
    ssrsa.set_key_pair(pub_key, priv_key)
    ssrsa_pub = secure_context.PublicKeyContext(ssrsa, self.__nonce_gen,
                                                self.__nonce_ver, self.__mac)
    ssrsa_priv = secure_context.PrivateKeyContext(ssrsa, self.__nonce_gen,
                                                  self.__nonce_ver, self.__mac)

    self.__manager.add_pkc_contexts(ssrsa_pub, ssrsa_priv)

  def add_goldwassermicali(self, conf_file):
    """ Initializes Goldwasser Micali.
    Args:
      conf_file: The JSON file to load configuration from. """
    # Load the configuration.
    config = self.__load_config(conf_file)
    key_size = config["key_size"]
    pub_key = config["pub_key"]
    priv_key = config["priv_key"]

    gm = GoldwasserMicali.GoldwasserMicali(key_size)
    gm.set_key_pair(pub_key, priv_key)
    gm_pub = secure_context.PublicKeyContext(gm, self.__nonce_gen,
                                             self.__nonce_ver, self.__mac)
    gm_priv = secure_context.PrivateKeyContext(gm, self.__nonce_gen,
                                               self.__nonce_ver, self.__mac)

    self.__manager.add_pkc_contexts(gm_pub, gm_priv)

  def add_blumgoldwasser(self):
    """ Initializes Blum-Goldwasser. """

    bg = BlumGoldwasser.BlumGoldwasser()
    # The key generation is really quick for this one, so we can do it on-the-fly.
    bg.gen_key_pair()
    bg_pub = secure_context.PublicKeyContext(bg, self.__nonce_gen,
                                             self.__nonce_ver, self.__mac)
    bg_priv = secure_context.PrivateKeyContext(bg, self.__nonce_gen,
                                               self.__nonce_ver, self.__mac)

    self.__manager.add_pkc_contexts(bg_pub, bg_priv)

  def get_manager(self):
    """ Gets the manager that we initialized.
    Returns:
      The manager. """
    return self.__manager
