import base64
import time


def gen_jwk(key, kid, nonce, url):
    if kid == 0:
        kid = int(time.time())
        jws_data = {
            "alg": "RS256",
            "jwk": {
                "kty": "RSA",
                "kid": str(kid),
                "alg": "RS256",
                "n": base64.urlsafe_b64encode(
                    key.public_key().public_numbers().n.to_bytes(length=256, byteorder="big")
                ).decode("ascii").replace("=", ""),
                "e": base64.urlsafe_b64encode(
                    key.public_key().public_numbers().e.to_bytes(length=3, byteorder="big")).decode().replace("=", "")

            },
            "nonce": f"{nonce}",
            "url": f"{url}"

        }
    else:
        jws_data = {
            "alg": "RS256",
            "kid": kid,
            "nonce": f"{nonce}",
            "url": f"{url}"

        }
    return jws_data
