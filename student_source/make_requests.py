import requests


def get_urls(url):
    print(f"GET : {url}")
    return requests.get(url)


def post_data(url, data):
    print(f"POST to: {url}")
    create_account_request = requests.post(url, headers={"Content-Type": "application/jose+json"},
                                           data=data)

    return create_account_request.headers, create_account_request.content.decode()


def get_nonce(url):
    print("GET Nonce")
    return requests.head(url)


def get_http(url):
    print(f"GET {url}")
    return requests.get(url)
