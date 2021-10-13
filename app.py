import os
import subprocess
import time

import student_source.functions as functions
import student_source.constants as constants
import student_source.dns as dns
from student_source.generate_key import generate_csr, gen_key_rsa

from urllib3.util import connection

key, _, _ = gen_key_rsa()

urls = functions.get_urls()
# nonce = functions.get_nonce(urls)

account_data = functions.create_account(key, urls)
kid = account_data["kid"]

domains = ["www.eth.ch", "eth.ch"]
ch_type = "http"

order = functions.create_order(domains, kid, urls, key)
authorizations = order["authorizations"]
finalize_url = order["finalize"]

challenge_to_validate = functions.get_challenges(authorizations[0], urls, kid, key, ch_type)
print(challenge_to_validate)
if ch_type == "http":
    if challenge_to_validate["status"] == "pending":
        print("Flask Should Launch")
        http_server_process = subprocess.Popen(
            args=["python3", "./student_source/http_challenge.py", challenge_to_validate["token"],
                  challenge_to_validate["domain"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        dns.dns_server("192.168.0.15")
        time.sleep(3)
        functions.send_challenge_validation_request(urls, challenge_to_validate["url"], key, kid)
        while True:
            time.sleep(2)
            challenge_to_check = functions.get_challenges(authorizations[0], urls, kid, key, ch_type)
            print(challenge_to_check)
            if challenge_to_check['status'] == "invalid":
                print("here1")
                http_server_process.kill()
                print(http_server_process.stdout.readlines())
                print(http_server_process.stderr.readlines())
                print("here")
                break
