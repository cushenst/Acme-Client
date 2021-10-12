import subprocess

import requests

from student_source.generate_key import generate_csr, sign_jws, sign_jws_rsa
import student_source.make_requests as http_request
from student_source.generate_jtw import sign_jwt

base_url = "https://localhost:14000/"

urls = http_request.get_urls(base_url)
nonce = http_request.get_nonce(urls)


signed_request_data = sign_jws_rsa(nonce, base_url, '{"termsOfServiceAgreed": true}', kid)

a = http_request.create_account(urls, signed_request_data)
print(a)
print(a.content.decode())



generate_csr()


a_child_process = subprocess.Popen(args=["python3", "./student_source/http_challenge.py"], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)


