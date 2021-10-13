import subprocess

import student_source.functions as functions
from student_source.generate_key import generate_csr, gen_key_rsa

key, _, _ = gen_key_rsa()

urls = functions.get_urls()
#nonce = functions.get_nonce(urls)

account_data = functions.create_account(key, urls)
kid = account_data["kid"]


domains = ["www.eth.ch", "eth.ch"]
ch_type = "dns"

functions.create_order(ch_type, domains, kid, urls, key)
functions.list_orders(key, kid, account_data["orders"])

#generate_csr()

#a_child_process = subprocess.Popen(args=["python3", "./student_source/http_challenge.py"], stdout=subprocess.DEVNULL,
#                                   stderr=subprocess.DEVNULL)
