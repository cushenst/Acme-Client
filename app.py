import subprocess
import sys
import time
import os

import student_source.constants as constants
import student_source.dns as dns
import student_source.functions as functions
from student_source.generate_key import gen_key_rsa

import click


@click.command()
@click.argument('challenge')
@click.option('--domain', required=True, help='Domains to issue cert with', multiple=True)
@click.option('--record', required=True, help='DNS response record of acme server')
@click.option('--dir', required=True, help='DIR of Acme server')
@click.option('--revoke', required=False, help='Revoke cert after issue', is_flag=True)
def startup(domain, dir, record, revoke, challenge):
    domains = []
    for i in domain:
        domains.append(i)
    #return domains, dir, record, revoke, challenge
    main(domains, dir, record, revoke, challenge)


def main(domains, dir_url, record, revoke, challenge):
    if "dns" in challenge:
        ch_type = "dns"
    if "http" in challenge:
        ch_type = "http"


    key, _, _ = gen_key_rsa()
    urls = functions.get_urls(dir_url)

    account_data = functions.create_account(key, urls)
    kid = account_data["kid"]

    for domain in domains:
        if "*" in domain:
            ch_type = "dns"

    order = functions.create_order(domains, kid, urls, key)
    authorizations = order["authorizations"]
    finalize_url = order["finalize"]
    ASSETS_DIR = os.path.dirname(os.path.abspath(__file__))

    for authorization in authorizations:
        challenge_to_validate = functions.get_challenges(authorization, urls, kid, key, ch_type)
        if ch_type == "http":
            challenge_key = functions.gen_challenge(key, challenge_to_validate["token"])
            if challenge_to_validate["status"] == "pending":
                print("Flask Should Launch")
                http_server_process = subprocess.Popen(
                    args=["python3", f"{ASSETS_DIR}/student_source/http_challenge.py", challenge_key,
                          challenge_to_validate["domain"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                dns_control = dns.dns_server(record)
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
        else:
            if challenge_to_validate["status"] == "pending":
                challenge_key = functions.gen_challenge_dns(key, challenge_to_validate["token"])
                dns_control = dns.dns_server_dns_challenge(challenge_key)
                time.sleep(1)
                functions.send_challenge_validation_request(urls, challenge_to_validate["url"], key, kid)
                for i in range(5):
                    time.sleep(1)
                    challenge_to_check = functions.get_challenges(authorization, urls, kid, key, ch_type)
                    if challenge_to_check['status'] != "pending":
                        print("challenge succeeded")
                        dns_control.stop()
                        dns_control.server.server_close()
                        break
    order_status = functions.check_order(urls, account_data["orders"], kid, key)
    if order_status["status"] == "ready":
        finalize_order_status = functions.finalize_order(urls, order_status["finalize"], kid, key, domains)
        for i in range(5):
            order_status = functions.check_order(urls, account_data["orders"], kid, key)
            time.sleep(1)
            if order_status["status"] == "valid":
                print("Cert Ready")
                cert_status = functions.check_order(urls, account_data["orders"], kid, key)
                certificate = functions.download_cert(urls, cert_status["certificate"], kid, key, domains[0])
                break
        if order_status["status"] != "valid":
            print("Challenge Invalid, \n Quitting...")
            sys.exit()

    else:
        print("Challenge Invalid, \n Quitting...")
        sys.exit()

    if revoke:
        functions.revoke_cert(urls, certificate, kid, key)

    dns_control = dns.dns_server(record)
    https_server_cert = subprocess.Popen(
        args=["python3", f"{ASSETS_DIR}/student_source/https_cert.py", domains[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    http_shutdown_server = subprocess.Popen(
        args=["python3", f"{ASSETS_DIR}/student_source/shutdown.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print("Servers Ready...")
    http_shutdown_server.wait()
    print(http_shutdown_server.stdout.read())
    print(http_shutdown_server.stderr.read())
    https_server_cert.terminate()
    dns_control.stop()
    dns_control.server.server_close()
    print(https_server_cert.stdout.read())
    print(https_server_cert.stderr.read())
    print("Shutdown signal received. \n Quitting...")

startup()