import json

import requests


def get_urls(base_url):
    url = base_url+"dir"
    request_response = requests.get(url, verify=False)
    urls = request_response.content.decode()
    urls = json.loads(urls)
    print(urls["newNonce"])
    return urls

def get_nonce(url):
    url = url["newNonce"]
    request_response = requests.head(url, verify=False)
    nonce = request_response.headers["Replay-Nonce"]
    return nonce


def create_account(url, data):
    url = url["newAccount"]
    create_account_request = requests.post(url, headers={"Content-Type": "application/jose+json"},
                                   data=data, verify=False)
    return create_account_request
