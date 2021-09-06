from urllib.parse import urlparse
from bs4 import BeautifulSoup
from whois import whois
import urllib.request
import pandas as pd
import ipaddress
import requests
import urllib
import re

'''Address Bar Based Features'''


def check_IPAddress(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0


def check_LongURL(url):
    if len(url) < 54:
        return 0
    return 1


def check_TinyURL(url):
    shortening_services = \
        r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
        r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
        r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
        r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
        r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
        r"tr\.im|link\.zip\.net"

    match = re.search(shortening_services, url)
    if match:
        return 1
    return 0


def check_AtSign(url):
    if "@" in url:
        return 1
    return 0


def check_Redirection(url):
    position = url.rfind('//')
    if position > 7:
        return 1
    return 0


def check_HTTPSDomain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1
    return 0


def check_PrefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1
    return 0


''' Domain Based Features'''


def check_DNSRecord(url):
    try:
        domain = whois(url).domain_name
        return 0
    except:
        return 1


def check_WEBTraffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url)
                             .read(), "lxml").find("REACH")['RANK']
        rank = int(rank)
    except TypeError:
        return 1
    if rank < 100000:
        return 1
    return 0


''' HTML and JS based features'''


def check_Iframe(response):
    if response != "":
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        return 1
    return 1


def check_Mouseover(response):
    if response != "":
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        return 0
    return 0


def check_RightClicking(response):
    if response != "":
        if re.findall(r"document.addEventListener('contextmenu', event => event.preventDefault())", response.text):
            return 1
        return 0
    return 1

def check_forwarding(response):
    if response != "":
        if len(response.history) < 2:
            return 0
        return 1
    return 1


def extract_features(url, malicious):

    features = []

    ''' Appending Address Bar Based Features '''

    features.append(check_IPAddress(url))
    features.append(check_LongURL(url))
    features.append(check_TinyURL(url))
    features.append(check_AtSign(url))
    features.append(check_Redirection(url))
    features.append(check_HTTPSDomain(url))
    features.append(check_PrefixSuffix(url))

    ''' Appending Domain Based Features '''

    features.append(check_DNSRecord(url))
    features.append(check_WEBTraffic(url))

    ''' Appendind HTML and Javascript Based Features'''

    try:
        response = requests.get(url)
    except:
        response = ""

    features.append(check_Iframe(response))
    features.append(check_Mouseover(response))
    features.append(check_RightClicking(response))
    features.append(check_forwarding(response))
    features.append(malicious)

    return features


if __name__ == '__main__':

    print("Starting Extraction...")

    header = ['ip', 'long_url', 'tiny_url', 'at', 'redirect', 'https', 'pre_suff',
              'dns', 'web_traffic', 'iframe', 'mouseover', 'rightclk_disable', 'forwarding', 'malicious']

    dataset = pd.read_csv('malicious_data.csv')

    urls = dataset['URLs'].to_list()

    features_data = [ extract_features(url,1) for url in urls[:10] ]

    pd.DataFrame(features_data).to_csv("MALICIOUS_sample.csv",index=False,header=header)
    print('Done Extraction!')


