#!/usr/bin/python3

import argparse
import logging
import sys

from final import config_helper
from final.transfer import server


logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


def main():
  parser = argparse.ArgumentParser("Test server script.")
  parser.add_argument("port", type=int, help="The port to listen on.")
  parser.add_argument("--rc4_conf", default="config/rc4.json",
                      help="RC4 configuration file.")
  parser.add_argument("--rsa_conf", default="config/rsa.json",
                      help="RSA configuration file.")
  parser.add_argument("--ssrsa_conf", default="config/ssrsa.json",
                      help="SSRSA configuration file.")
  parser.add_argument("--gm_conf", default="config/gm.json",
                      help="GM configuration file.")
  args = parser.parse_args()

  # Initialize the cryptosystems.
  config = config_helper.ConfigHelper()
  config.add_rc4(args.rc4_conf)
  config.add_des()
  config.add_rsa(args.rsa_conf)
  config.add_ssrsa(args.ssrsa_conf)
  config.add_goldwassermicali(args.gm_conf)
  config.add_blumgoldwasser()
  manager = config.get_manager()

  # Run the server.
  my_server = server.Server(args.port, manager)
  my_server.handle_client()


if __name__ == "__main__":
  main()
