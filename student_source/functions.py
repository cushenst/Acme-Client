import base64
import json

import student_source.constants as constants
import student_source.make_requests as http_requests
from student_source.generate_key import sign_jws_rsa, gen_thumbprint, generate_csr, save_cert, gen_dns_hash, pem_to_der


def create_account(key, urls):
    url = urls["newAccount"]
    nonce = get_nonce(urls)
    create_account_payload = sign_jws_rsa(key, nonce, url, '{"termsOfServiceAgreed": true}')
    create_account_response_header, create_account_response_body = http_requests.post_data(url, create_account_payload)
    account_data = json.loads(create_account_response_body)
    response_data = {
        "orders": account_data["orders"],
        "kid": account_data["orders"].replace("list-orderz", "my-account")
    }
    return response_data


def get_urls(url):
    request_response = http_requests.get_urls(url)
    urls = request_response.content.decode()
    urls = json.loads(urls)
    return urls


def get_nonce(urls):
    url = urls["newNonce"]
    request_response = http_requests.get_nonce(url)
    nonce = request_response.headers["Replay-Nonce"]
    return nonce


def list_orders(key, kid, orders_url, urls):
    nonce = get_nonce(urls)
    list_orders_payload = sign_jws_rsa(key, nonce, orders_url, '', kid)
    list_orders_response_header, list_orders_response_body = http_requests.post_data(orders_url, list_orders_payload)
    return json.loads(list_orders_response_body)


def create_order(domains, auth, urls, key):
    identifiers = []
    for domain in domains:
        identifiers.append({"type": "dns", "value": domain})
    payload = json.dumps({
        "identifiers": identifiers
    })

    url = urls["newOrder"]
    nonce = get_nonce(urls)
    signed_payload = sign_jws_rsa(key, nonce, url, payload, auth)
    response_header, response_body = http_requests.post_data(url, signed_payload)
    return json.loads(response_body)


def get_challenges(auth_url, urls, kid, key, challenge_type):
    nonce = get_nonce(urls)
    signed_payload = sign_jws_rsa(key, nonce, auth_url, "", kid)
    header, body = http_requests.post_data(auth_url, signed_payload)
    body = json.loads(body)
    challenges = body["challenges"]
    for challenge in challenges:
        if challenge_type in challenge["type"]:
            return {"url": challenge["url"], "token": challenge["token"], "status": challenge["status"],
                    "domain": body["identifier"]["value"]}
    return {"status": "Not Found"}


def check_http_server(url, token):
    response = http_requests.get_http(url)
    decoded_body = response.content.decode()


def send_challenge_validation_request(urls, url, key, kid):
    nonce = get_nonce(urls)
    signed_payload = sign_jws_rsa(key, nonce, url, "{}", kid)
    header, body = http_requests.post_data(url, signed_payload)


def check_challenge_validation_request(urls, url, key, kid):
    nonce = get_nonce(urls)
    signed_payload = sign_jws_rsa(key, nonce, url, "{}", kid)
    header, body = http_requests.post_data(url, signed_payload)


def gen_challenge(key, token):
    thumbprint = gen_thumbprint(key)
    return f"{token}.{thumbprint}"


def check_order(urls, url, kid, key):
    nonce = get_nonce(urls)
    orders = list_orders(key, kid, url, urls)
    if len(orders["orders"]) > 0:
        post_as_get = sign_jws_rsa(key, nonce, orders["orders"][0], "", kid)
        header, order_details = http_requests.post_data(orders["orders"][0], post_as_get)
        order_details = json.loads(order_details)
        return order_details
    else:
        return {"status": "invalid"}


def finalize_order(urls, url, kid, key, domains):
    nonce = get_nonce(urls)
    csr = generate_csr(domains)
    payload = {
        "csr": base64.urlsafe_b64encode(csr).decode().replace("=", "")
    }
    payload = json.dumps(payload)
    signed_csr_payload = sign_jws_rsa(key, nonce, url, payload, kid)
    header, order_details = http_requests.post_data(url, signed_csr_payload)
    return json.loads(order_details)


def download_cert(urls, url, kid, key):
    nonce = get_nonce(urls)
    signed_download_cert_payload = sign_jws_rsa(key, nonce, url, "", kid)
    header, cert_details = http_requests.post_data(url, signed_download_cert_payload)
    save_cert(cert_details.encode())
    return cert_details


def gen_challenge_dns(key, token):
    http_challenge = gen_challenge(key, token)
    dns_challenge = gen_dns_hash(http_challenge)
    print(dns_challenge)
    return dns_challenge


def revoke_cert(urls, cert, kid, key):
    nonce = get_nonce(urls)
    url = urls["revokeCert"]

    payload = {
        "certificate": pem_to_der(cert)
    }
    signed_revoke_cert_payload = sign_jws_rsa(key, nonce, url, json.dumps(payload), kid)
    header, cert_details = http_requests.post_data(url, signed_revoke_cert_payload)
