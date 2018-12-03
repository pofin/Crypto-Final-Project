#!/usr/bin/python3

import logging
import sys

from final.transfer import client
from final.crypto import crypto_manager, stupid_symmetric, secure_context
from final.crypto import GoldwasserMicali, SSRSA, BlumGoldwasser
from final.crypto import HMAC, stupid_pkc, RSA, RC4, sequential_nonce

# Keys to use for testing.
RSA_SIZE = 1024
RSA_E = 137756442533670035557724382674694510804208984231103548649815638511590294834826575401245886677864358232450808715288975122785974948336685389725335101136214560153613389346294330250235627407112166222813030048329737230589762154610119811763369182814410975087736743945801749771979817010029562199760538719364455510951
RSA_D = 1089024077030639922920182304796114169372742684083936744426837455254569830195635343155778821826965455954347878702760769083764084462366267416536025612282266351666006699039739190774193705328521193692648582138879002562845756937352264112320952918454454446755590251196108742317020997315292509834828103586632457667
RSA_N = 192202886425938235333898592428612949950416561294942136261733698235900692022494563016745482316656307960617370841249634260204214686654944530843629245216839910888753243846792817725635986957057073285002726557061766140467593877555330490231658425503912592758538803797744361430117092370937254540688446127785627889749

GM_SIZE = 1024
GM_PUB = (12894680526077081283448533636628347548961481466383193272448008028206604121645673584077625953451359362165556553347317254116186631846680799141082409427035662, 193662806032308495945627477987262435919177783281322851088951346750389891244542922981529140836777610496017494975889094670522402067665020027412249092980316565257494538642948721367802768978887694371862626913028620816167468992427800828241016217354193447681951181560843501197125872881720723887447261880233970652937)
GM_PRIV = (13541032084033133502423096942588412271694220921233053434889708221651269291053875704936711888121459171482750539984903701276599867485763838355091589099203277, 14301923577942437664938537260617109412560541586636495630120649968379435747671235628113658826485254196895535262928931235850712025159814679075121890819937581)

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

my_client = client.Client("127.0.0.1", 1337, manager)

# Send a message.
my_client.send_message("Hello World!")
