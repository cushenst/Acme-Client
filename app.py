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

for authorization in authorizations:
    challenge_to_validate = functions.get_challenges(authorization, urls, kid, key, ch_type)
    challenge_key = functions.gen_challenge(key, challenge_to_validate["token"])
    if ch_type == "http":
        if challenge_to_validate["status"] == "pending":
            print("Flask Should Launch")
            http_server_process = subprocess.Popen(
                args=["python3", "./student_source/http_challenge.py", challenge_key,
                      challenge_to_validate["domain"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            dns_control = dns.dns_server(constants.local_ip)
            time.sleep(1)
            functions.send_challenge_validation_request(urls, challenge_to_validate["url"], key, kid)
            for i in range(5):
                time.sleep(1)
                challenge_to_check = functions.get_challenges(authorization, urls, kid, key, ch_type)
                if challenge_to_check['status'] != "pending":
                    print("challenge succeeded")
                    http_server_process.kill()
                    dns_control.stop()
                    dns_control.server.server_close()
                    break

order_status = functions.check_order(urls, account_data["orders"], kid, key)
if order_status["status"] == "ready":
    finalize_order_status = functions.finalize_order(urls, order_status["finalize"], kid, key, domains)
    for i in range(5):
        order_status = functions.check_order(urls, account_data["orders"], kid, key)
        time.sleep(1)
        print(order_status)
        if order_status["status"] == "valid":
            print("Cert Ready")
            cert_status = functions.check_order(urls, account_data["orders"], kid, key)
            certificate = functions.download_cert(urls, cert_status["certificate"], kid, key)
            break

else:
    print("Challenge Invalid, \n Quitting...")

