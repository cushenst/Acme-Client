from student_source.generate_key import sign_jws_rsa
import student_source.make_requests as http_requests
import json
import student_source.constants as constants


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


def get_urls():
    url = constants.base_url + "/dir"
    request_response = http_requests.get_urls(url)
    urls = request_response.content.decode()
    urls = json.loads(urls)
    return urls


def get_nonce(urls):
    url = urls["newNonce"]
    request_response = http_requests.get_nonce(url)
    nonce = request_response.headers["Replay-Nonce"]
    return nonce


def list_orders(key, kid, orders_url):
    nonce = get_nonce(get_urls())
    list_orders_payload = sign_jws_rsa(key, nonce, orders_url, '', kid)
    list_orders_response_header, list_orders_response_body = http_requests.post_data(orders_url, list_orders_payload)
    print(list_orders_response_header)
    print(list_orders_response_body)


def create_order(challenge_type, domains, auth, urls, key):
    identifiers = []
    for domain in domains:
        identifiers.append({"type": challenge_type, "value": domain})
    payload = json.dumps({
        "identifiers": identifiers
    })

    url = urls["newOrder"]
    nonce = get_nonce(urls)
    signed_payload = sign_jws_rsa(key, nonce, url, payload, auth)
    response_header, response_body = http_requests.post_data(url, signed_payload)
    print(response_body)
    return response_body
