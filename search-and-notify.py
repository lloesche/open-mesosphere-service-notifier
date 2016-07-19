#!/usr/bin/env python3
import sys
import argparse
import logging
import shodan
from pprint import pprint
from ipwhois import IPWhois
from multiprocessing.pool import ThreadPool

TAKE_SCREENSHOT = True
try:
    from selenium import webdriver
except ImportError:
    TAKE_SCREENSHOT = False
    pass

LOG_LEVEL = logging.DEBUG
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(LOG_LEVEL)
logging.getLogger('OpenServices').setLevel(LOG_LEVEL)


def main(argv):
    p = argparse.ArgumentParser(description='Search Shodan for Open Mesosphere Services')
    p.add_argument('--api-key', help='Shodan API Key', required=True)
    args = p.parse_args(argv)

    s = OpenServices(args.api_key, TAKE_SCREENSHOT)
    s.marathons()


class OpenServices:
    def __init__(self, api_key, _screenshot = False):
        self.log = logging.getLogger(self.__class__.__name__)
        self.shodan = shodan.Shodan(api_key)
        self._screenshot = _screenshot
        self.tp = ThreadPool(10)

    def marathons(self):
        return self.search('X-Marathon-Leader')

    def process(self, shodan_data):
        self.log.debug('Processing IP {}'.format(shodan_data['ip_str']))
        data = {'shodan': shodan_data,
                'whois': self.whois(shodan_data['ip_str']),
                'screen': self.screenshot(shodan_data['ip_str'], shodan_data['port'])}
        pprint(data)

    def search(self, what):
        try:
            results = self.shodan.search(what)
            self.log.info('Results found: {}'.format(results['total']))
            self.tp.map(self.process, results['matches'])

        except shodan.APIError as e:
            self.log.error('Shodan API Error: {}'.format(e))

    def whois(self, ip):
        self.log.debug('Fetching WHOIS data for {}'.format(ip))
        w = IPWhois(ip, timeout=10)
        return w.lookup_rdap(depth=1, retry_count=5, rate_limit_timeout=60)

    def screenshot(self, host, port):
        if self._screenshot:
            if ':' in host:
                url = 'http://[{}]:{}/'.format(host, port)
            else:
                url = 'http://{}:{}/'.format(host, port)
            self.log.debug('Capturing screenshot of {}'.format(url))
            browser = webdriver.PhantomJS()
            browser.set_window_size(1024, 768)
            browser.get(url)
            png = browser.get_screenshot_as_base64()
            browser.quit()
            return png


if __name__ == "__main__":
    main(sys.argv[1:])
