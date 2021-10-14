import base64
import json
import time

from cryptography import x509
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.x509.oid import NameOID

import student_source.generate_jtw as jwt


def generate_csr(domains):
    key = write_key_rsa()
    csr = write_csr(key, domains)
    return csr


def gen_key_rsa():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    key_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption())
    public_key_bytes = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    return key, key_bytes, public_key_bytes


def gen_key_ecc():
    private_key = ec.generate_private_key(ec.SECP256R1(), backend)
    print(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    public_key_point = private_key.public_key().public_bytes(serialization.Encoding.X962,
                                                             serialization.PublicFormat.UncompressedPoint)
    print(private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo))
    public_key1 = private_key.public_key()
    public_key = public_key1.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    sizeBytes = (len(public_key_point) - 1) // 2
    partition = 1
    x_bytes = public_key_point[partition:(partition + sizeBytes)]
    partition += sizeBytes
    y_bytes = public_key_point[partition:partition + sizeBytes]
    pointx = base64.urlsafe_b64encode(x_bytes)
    pointy = base64.urlsafe_b64encode(y_bytes)

    return pointx, pointy, private_key, public_key, public_key1


def sign_jws_rsa(key, nonce, url, payload, kid=0):
    jws_data = jwt.gen_jwk(key, kid, nonce, url)

    protected = json.dumps(jws_data)
    protected64 = base64.urlsafe_b64encode(protected.encode("utf-8")).decode("ascii").replace("=", "")
    payload64 = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").replace("=", "")
    data64 = f"{protected64}.{payload64}"

    signature = key.sign(data64.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    sig64 = base64.urlsafe_b64encode(signature).decode("ascii").replace("=", "")
    return json.dumps({
        "protected": protected64,
        "payload": payload64,
        "signature": sig64
    })


def sign_jws(nonce, base_url, payload_data):
    _, _, private_ec_key, public_ec_key1, public_ec_key = gen_key_ecc()
    signature_algorithm = ec.ECDSA(hashes.SHA256())
    curve = ec.SECP256R1()
    jws_data = {
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "kid": "test",
            "x": base64.urlsafe_b64encode(
                public_ec_key.public_numbers().x.to_bytes(length=32, byteorder="big")).decode().replace("=", ""),
            "y": base64.urlsafe_b64encode(
                public_ec_key.public_numbers().y.to_bytes(length=32, byteorder="big")).decode().replace("=", "")

        },
        "nonce": f"{nonce}",
        "url": f"{base_url}sign-me-up"

    }

    payload_data = {
        "termsOfServiceAgreed": "true",
        "contact": [
            "mailto:cert-admin@example.org",
            "mailto:admin@example.org"
        ]
    }

    protected = json.dumps(jws_data)
    payload = json.dumps(payload_data)
    protected64 = base64.urlsafe_b64encode(protected.encode("utf-8")).decode().replace("=", "")
    payload64 = base64.urlsafe_b64encode(payload.encode()).decode().replace("=", "")
    data64 = f"{protected64}.{payload64}".encode()
    signature_der = private_ec_key.sign(data64, signature_algorithm)
    rs_num = utils.decode_dss_signature(signature_der)
    print(rs_num)
    signature = int(str(rs_num[0]) + str(rs_num[1]))
    sig_byte = signature.to_bytes(length=64, byteorder="big")
    sig64 = base64.urlsafe_b64encode(sig_byte).decode().replace("=", "")
    print(f'Protected: {protected64}')
    print(f"Payload: {payload64}")
    print(f'Signature: {sig64}')
    auth = {
        "protected": protected64,
        "payload": payload64,
        "signature": sig64
    }
    return json.dumps(auth)
    # try:
    #     public_ec_key.verify(signature, data64, signature_algorithm)
    #     print('Verification OK')
    # except InvalidSignature:
    #     print('Verification failed')


def write_key_rsa():
    key, _, _ = gen_key_rsa()
    with open("./student_source/certs/key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    return key


def save_cert(cert):
    with open("./student_source/certs/fullchain.pem", "wb") as f:
        f.write(cert)


def write_csr(key, domains):
    dns_name = []
    for domain in domains:
        dns_name.append(x509.DNSName(domain))
    print(domains)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zürich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ETH NetSec"),
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ])).add_extension(
        x509.SubjectAlternativeName(dns_name),
        critical=False,
    )

    signed_csr = csr.sign(key, hashes.SHA256())

    # Write our CSR out to disk.
    with open("./student_source/certs/csr.pem", "wb") as f:
        f.write(signed_csr.public_bytes(serialization.Encoding.PEM))

    return signed_csr.public_bytes(serialization.Encoding.DER)


def gen_thumbprint(key):
    digest = hashes.Hash(hashes.SHA256())

    thumbprint_data = {
        "e": base64.urlsafe_b64encode(key.public_key().public_numbers().e.to_bytes(length=3, byteorder="big")).decode(
            "ascii").replace("=", ""),
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(key.public_key().public_numbers().n.to_bytes(length=256, byteorder="big")).decode(
            "ascii").replace("=", "")
    }
    clean_thumbprint_data = json.dumps(thumbprint_data).replace(" ", "")
    digest.update(clean_thumbprint_data.encode("ascii"))
    thumbprint = digest.finalize()
    return base64.urlsafe_b64encode(thumbprint).decode("ascii").replace("=", "")


def gen_dns_hash(key_authorization):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key_authorization.encode("ascii"))
    key_hash = digest.finalize()
    return base64.urlsafe_b64encode(key_hash).decode("ascii").replace("=", "")
