import datetime
from optparse import OptionParser

from . import Fingerprinters, Loggers


class ScannerResult(object):
    def __init__(self, target_url):
        self.url = target_url
        self.apps = {}
        self.plugins = {}

    def print_results(self, file):
        pass

    def __str__(self):
        string_name = ""
        string_name += "Scanner Results for %s\n" % url

        for app, vers in self.apps.items():
            versions_as_str = [v.vstring for v in vers]
            string_name += "  - %s: %s\n" % (app, versions_as_str)

            if app in self.plugins:
                for plugin, app_vers in self.plugins[app].items():
                    versions_as_str = [v.vstring for v in app_vers]
                    string_name += "    -- %s: %s\n" % (plugin, versions_as_str)
        return string_name


class Scanner(object):
    def __init__(self, target_url, scan_plugins=False):
        self.url = target_url
        self.scan_plugins = scan_plugins
        self.result = ScannerResult(target_url)
        self.logger = Loggers.FileLogger(open("/dev/null", "w"))
        self.app_guesser = Fingerprinters.WebAppGuesser(target_url, logger=self.logger)

    def scan(self):

        possible_apps = self.app_guesser.guess_apps()

        for app_name in possible_apps:
            fp = Fingerprinters.WebAppFingerprinter(self.url, app_name, logger=self.logger)
            self.result.apps[app_name] = fp.fingerprint()

        if self.scan_plugins:
            for app_name in possible_apps:
                pg = Fingerprinters.PluginGuesser(self.url, app_name)
                self.result.plugins[app_name] = {}

                possible_plugins = pg.guess_plugins()

                for plugin_name in possible_plugins:
                    pfp = Fingerprinters.PluginFingerprinter(self.url, app_name, plugin_name, logger=self.logger)
                    self.result.plugins[app_name][plugin_name] = pfp.fingerprint()


if __name__ == '__main__':
    USAGE = "usage: %prog [options] url"
    EPILOGUE = """Check a URL for any webapps supported by BlindElephant, and 
               fingerprint any found. With optional -p, also detect and fingerprint
               plugins (not all supported apps have supported plugins)."""

    parser = OptionParser(usage=USAGE, epilog=EPILOGUE)
    parser.add_option("-p", "--plugins", action="store_true", help="Detect and fingerprint plugins too")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        print("Error: url is required argument\n")
        parser.print_help()
        quit()

    url = args[0].strip("/")

    start = datetime.datetime.now()
    s = Scanner(url, options.plugins)
    s.scan()
    finish = datetime.datetime.now()
    print(s.result)
    print("Fingerprint time: ", finish - start)
