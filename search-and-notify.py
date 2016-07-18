#!/usr/bin/env python3
import sys
import argparse
import logging
import shodan
from pprint import pprint
from ipwhois import IPWhois

TAKE_SCREENSHOT = True
try:
    from PySide.QtCore import QUrl, QBuffer, QByteArray
    from PySide.QtGui import QApplication, QImage, QPainter
    from PySide.QtWebKit import QWebView
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
    def __init__(self, api_key, take_screenshot = False):
        self.log = logging.getLogger(self.__class__.__name__)
        self.api = shodan.Shodan(api_key)
        self._screenshot = Screenshot() if take_screenshot else None

    def marathons(self):
        return self.search('X-Marathon-Leader')

    def search(self, what):
        try:
            results = self.api.search(what)
            self.log.info('Results found: {}'.format(results['total']))
            for shodan_data in results['matches']:
                print('IP: %s' % shodan_data['ip_str'])
                whois = IPWhois(shodan_data['ip_str'])
                whois_data = whois.lookup_rdap(depth=1)
                screen_data = self.screenshot(shodan_data['ip_str'], shodan_data['port'])
                data = {'shodan': shodan_data,
                        'whois':  whois_data,
                        'screen': screen_data}
                pprint(data)

        except shodan.APIError as e:
            self.log.error('Shodan API Error: {}'.format(e))

    def screenshot(self, host, port):
        if self._screenshot:
            url = 'http://{}:{}/'.format(host, port)
            self.log.debug('Capturing screenshot of {}'.format(url))
            return self._screenshot.capture(url)


class Screenshot(QWebView):
    def __init__(self):
        self.app = QApplication(sys.argv)
        QWebView.__init__(self)
        self._loaded = False
        self.loadFinished.connect(self._load_finished)

    def capture(self, url):
        self.load(QUrl(url))
        self.wait_load()
        frame = self.page().mainFrame()
        self.resize(frame.contentsSize())
        self.page().setViewportSize(frame.contentsSize())
        image = QImage(self.page().viewportSize(), QImage.Format_ARGB32)
        painter = QPainter(image)
        frame.render(painter)
        painter.end()
        data = QByteArray()
        buf = QBuffer(data)
        image.save(buf, 'PNG')
        return data.toBase64()

    def wait_load(self):
        while not self._loaded:
            self.app.processEvents()
        self._loaded = False

    def _load_finished(self, result):
        self._loaded = True


if __name__ == "__main__":
    main(sys.argv[1:])
