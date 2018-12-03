#!/usr/bin/python3

import logging
import sys

from final.crypto import crypto_manager, stupid_symmetric, secure_context
from final.crypto import HMAC, stupid_pkc, RSA, RC4, sequential_nonce
from final.crypto import GoldwasserMicali, SSRSA, BlumGoldwasser
from final.transfer import server

# Keys to use for testing.
RSA_SIZE = 1024
RSA_E = 172243570653571995002623586717353333288672688819101819197611917694403993226621608218071589702246934888934946471718591530563471841597324228859279538755423078698815201058339281264920445828883088518003877168829990685241070810737622670649886607845917263983722867252143444516186656588411692903338856873127593590279
RSA_D = 138848627394245553420578081214197920279252836539108224461879355995643942958514122529019743959409741235583752434179929106566638250350200277846806513384281455226994518745884342836094624941277927841801225477154730976256598665050263820966466976251199224691814681772547097112193038923701089232385737221902290876199
RSA_N = 141426329778690437762889224941196900696752020619302367877080626587289986710518115040387344515060790754393792083744871627725537163878138739261193375415240361168043762895903786737402586347632039033155760780909859170702692791121339991094875426780480024864436045817173596987138125675111414041873794812142531716763

GM_SIZE = 1024
GM_PUB = (8434096311533483075050588840858313699462040022581577275579835907890533055644950863465043733716140206908879190818404670853257873737030921185934182604430040, 310720341921728988508381499219343658847470330169859500125185535026884847198760782754356560772636519522119692326883386545802158420960294163678113372844606062606646748335907763058977076593784508066995637457198660633572174256358380120351582913539437068440249787277580059841083702697324101261528317832919682318071)
GM_PRIV = (14454015544444333574074198666920919912976957760577319527803787616955291543254287804905837113912859254682056295334706607234431467187303129452259620790710177, 21497163951865269753939194949802587412622627645151262676132112190614616982735523295843226111584816218002286060255093837320324429275224469354328741046192023)

RC4_SIZE = 256
NONCE_SIZE = 32

MAC_DEFAULT_KEY = "mac_secret"

logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

# Create some contexts.
stupid_crypto = stupid_symmetric.StupidCrypto()
rc4 = RC4.RC4(RC4_SIZE)
stupid_pkc_crypto = stupid_pkc.StupidCrypto()
rsa = RSA.RSA(RSA_SIZE)
rsa.set_key_pair((RSA_E, RSA_N), RSA_D)
ssrsa = SSRSA.SSRSA(RSA_SIZE)
ssrsa.set_key_pair((RSA_E, RSA_N), RSA_D)
gm = GoldwasserMicali.GoldwasserMicali(GM_SIZE)
gm.set_key_pair(GM_PUB, GM_PRIV)
bg = BlumGoldwasser.BlumGoldwasser()
# The key generation is really quick for this one, so we can do it on-the-fly.
bg.gen_key_pair()
nonce_gen = sequential_nonce.SequentialNonceGenerator(NONCE_SIZE)
nonce_ver = sequential_nonce.SequentialNonceVerifier(NONCE_SIZE)
mac = HMAC.HMAC(MAC_DEFAULT_KEY)
stupid_pub = secure_context.PublicKeyContext(stupid_pkc_crypto, nonce_gen,
                                             nonce_ver, mac)
stupid_priv = secure_context.PrivateKeyContext(stupid_pkc_crypto, nonce_gen,
                                               nonce_ver, mac)
rsa_pub = secure_context.PublicKeyContext(rsa, nonce_gen, nonce_ver, mac)
rsa_priv = secure_context.PrivateKeyContext(rsa, nonce_gen, nonce_ver, mac)
ssrsa_pub = secure_context.PublicKeyContext(ssrsa, nonce_gen, nonce_ver, mac)
ssrsa_priv = secure_context.PrivateKeyContext(ssrsa, nonce_gen, nonce_ver, mac)
gm_pub = secure_context.PublicKeyContext(gm, nonce_gen, nonce_ver, mac)
gm_priv = secure_context.PrivateKeyContext(gm, nonce_gen, nonce_ver, mac)
bg_pub = secure_context.PublicKeyContext(bg, nonce_gen, nonce_ver, mac)
bg_priv = secure_context.PrivateKeyContext(bg, nonce_gen, nonce_ver, mac)
stupid_con = secure_context.SymmetricContext(stupid_crypto, nonce_gen,
                                             nonce_ver, mac)
rc4_con = secure_context.SymmetricContext(rc4, nonce_gen, nonce_ver, mac)

# Add them to the manager.
manager = crypto_manager.CryptoManager()
manager.add_pkc_contexts(stupid_pub, stupid_priv)
manager.add_pkc_contexts(rsa_pub, rsa_priv)
manager.add_pkc_contexts(ssrsa_pub, ssrsa_priv)
manager.add_pkc_contexts(gm_pub, gm_priv)
manager.add_pkc_contexts(bg_pub, bg_priv)
manager.add_symmetric_context(stupid_con)
manager.add_symmetric_context(rc4_con)

my_server = server.Server(1337, manager)
my_server.handle_client()