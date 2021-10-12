import base64

from student_source.generate_key import gen_key_rsa


def sign_jwt():
    _, private_key, public_key = gen_key_rsa()
    #print(public_key)

    # data = {
    #     "alg": self._algorithm,
    #     "kty": "EC",
    #     "crv": crv,
    #     "x": long_to_base64(public_key.pubkey.point.x(), size=key_size).decode("ASCII"),
    #     "y": long_to_base64(public_key.pubkey.point.y(), size=key_size).decode("ASCII"),
    # }


