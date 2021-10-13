import requests


def get_urls(url):
    print(f"get to: {url}")
    return requests.get(url, verify=False)


def post_data(url, data):
    print(f"post to: {url}")
    create_account_request = requests.post(url, headers={"Content-Type": "application/jose+json"},
                                           data=data, verify=False)

    return create_account_request.headers, create_account_request.content.decode()


def get_nonce(url):
    print("get Nonce")
    return requests.head(url, verify=False)