"""Fingerprinter and Guesser objects for WebApps and their plugins"""
import hashlib
import http.server
import itertools
import os
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPException

from . import DifferencesTables, Configuration as Configuration, FileMassagers, FingerprintUtils
from .Loggers import FileLogger

# Number of consecutive low-level communication failures to tolerate before giving up
HOST_DOWN_THRESHOLD = 2


# TODO:
# - implement winnowing
# - stop early on consistent and accurate results + make this configurable


class WebAppFingerprinter(object):
    """Class that encapsulates the data and functions needed to use a 
    BlindElephant fingerprint db to attempt to get the version of a web
    app.
    """

    def __init__(self, url, app_name, num_probes=15, logger=FileLogger(), winnow=False):
        """Expects the url where a (supported) webapp is installed, the name of
        the web app, an optional number of files to check while guessing the
        version, and an optional logger object supporting the operations in 
        BlindElephantLogger (default is a FileLogger tied to sys.stdout)
        """
        self.best_guess = None
        self.error_page_fingerprint = None
        self.ver_list = None
        self.url = url
        self.app_name = app_name
        self.num_probes = num_probes
        self.logger = logger
        self.winnow = winnow
        self._host_down_errors = 0
        self._error_page_fingerprint = None

    def _load_db(self):
        self.path_nodes, self.version_nodes, self.all_versions = \
            DifferencesTables.loadTables(Configuration.getDbPath(self.app_name), printStats=False)
        self.logger.logLoadDB(Configuration.getDbPath(self.app_name), self.all_versions,
                              self.path_nodes, self.version_nodes)

    def fingerprint(self):
        """Select num_probes most useful paths, and fetch them
        from the site at url. Return an ordered list of possible versions or 
        [].
        """
        self._load_db()
        paths = FingerprintUtils.pick_fingerprint_files(self.path_nodes, self.all_versions)
        self.logger.logStartFingerprint(self.url, self.app_name)
        self.error_page_fingerprint = FingerprintUtils.identify_error_page(self.url)

        possible_vers = []
        for path in paths[:self.num_probes]:
            if curr_vers := self.fingerprint_file(path):
                possible_vers.append(curr_vers)
            if self._host_down_errors >= HOST_DOWN_THRESHOLD:
                break

        ver_set = FingerprintUtils.collapse_version_possibilities(possible_vers)
        self.ver_list = list(ver_set)

        # if more than one possibility, try to narrow it by winnowing!
        if len(self.ver_list) > 1 and self.winnow:
            print("ver_list before winnowing:")
            for v in self.ver_list:
                print(v.vstring)
            print("\n")
            self.winnow_versions(possible_vers)

        ver_set = FingerprintUtils.collapse_version_possibilities(possible_vers)
        self.ver_list = sorted(ver_set)
        if len(self.ver_list) > 1:
            self.best_guess = FingerprintUtils.pick_likely_version(self.ver_list)
        elif len(self.ver_list) == 1:
            self.best_guess = self.ver_list[0]
        self.logger.logFinishFingerprint(self.ver_list, self.best_guess)
        return self.ver_list

    def fingerprint_file(self, path):
        """Fingerprint a single file given the path, and return a list
        possible versions implied by the result, or None if no information
        could be gleaned.
        """
        try:
            url = self.url + (path if path.startswith("/") else f"/{path}")
            data = FingerprintUtils.url_read_spoof_ua(url)
            self._host_down_errors = 0
            digest_hash = hashlib.md5(f"{data}{path}".encode('utf-8')).hexdigest()
            if digest_hash in self.path_nodes:
                possible_vers = self.path_nodes[path][digest_hash]
                self.logger.logFileHit(path, possible_vers, None, None, False)
                return possible_vers
            else:
                ms = FileMassagers.MASSAGERS
                for i in range(1, len(ms) + 1):
                    for massagersTpl in itertools.combinations(ms, i):
                        massagedData = data
                        for m in massagersTpl:
                            massagedData = m(massagedData)
                        massaged_hash = hashlib.md5(f'{massagedData}{path}'.encode('utf-8')).hexdigest()
                        if massaged_hash in self.path_nodes[path]:
                            possible_vers = self.path_nodes[path][massaged_hash]
                            self.logger.logFileHit(path, possible_vers, "", None, False)
                            return possible_vers
                if FingerprintUtils.compare_to_error_page(self.error_page_fingerprint, data):
                    self.logger.logFileHit(path, None, None, 'Detected Custom 404', True)
                    return None
                if not hasattr(self.path_nodes[path], digest_hash):
                    raise KeyError
        except IOError as e:
            if hasattr(e, 'reason'):
                self.logger.logFileHit(path, None, None, f"Failed to reach a server: {e.reason}", True)

                self._host_down_errors += 1
            elif hasattr(e, 'code'):
                self.logger.logFileHit(path, None, None,
                                       f'Error code: {e.code} '
                                       f'({http.server.BaseHTTPRequestHandler.responses[e.code][0]})', True)

        except HTTPException as e2:
            self.logger.logFileHit(path, None, None, f'Error: {e2} ', True)
        except KeyError as e2:
            self.logger.logFileHit(path, None, None,
                                   "Retrieved file doesn't match known fingerprint. %s" % e2.args, True)

        return None

    def winnow_versions(self, possible_vers):
        winnow_attempts = 0
        while len(self.ver_list) > 1 and winnow_attempts < self.num_probes:
            winnow_paths = FingerprintUtils.pick_winnow_files(self.ver_list, self.version_nodes,
                                                              self.num_probes - winnow_attempts)
            if not winnow_paths:
                break
            for path in winnow_paths:
                winnow_attempts += 1
                if curr_vers := self.fingerprint_file(path):
                    possible_vers.append(curr_vers)
                    tmp_ver_set = FingerprintUtils.collapse_version_possibilities(possible_vers)
                    # if winnowing knocked out a possibility, pick again winnow files base on this new info
                    if len(tmp_ver_set) < len(self.ver_list):
                        self.ver_list = list(tmp_ver_set)
                        print("winnow eliminated a version... picking again")
                        continue
                if self._host_down_errors >= HOST_DOWN_THRESHOLD:
                    break
                if winnow_attempts > self.num_probes:
                    break


class PluginFingerprinter(WebAppFingerprinter):
    """Fingerprint the plugins of a particular webapp, using the same approach
    as WebAppFingerprinter. (Will find the plugins installation directory
    of configured apps automatically) 
    """

    # TODO: Revisit logging to differentiate plugin fingerprint output from app fingerprint output
    def __init__(self, url, app_name, plugin_name, num_probes=15, logger=FileLogger(), winnow=False):
        """Same params as WebAppFingerprinter plus the name of plugin to 
        fingerprint. 
        """
        if "pluginsRoot" not in Configuration.APP_CONFIG[app_name]:
            raise NotImplementedError(f"Couldn't find pluginsRoot entry for {app_name} in WebAppConfiguration. "
                                      f"Plugins may not be supported for this app")
        self.plugin_name = plugin_name
        super(PluginFingerprinter, self).__init__(url +
                                                  Configuration.APP_CONFIG[app_name]["pluginsRoot"] + plugin_name,
                                                  app_name, num_probes=num_probes)
        # super doesn't take keyword args; this is getting more and more annoying
        self.num_probes = num_probes
        self.logger = logger
        self.winnow = winnow

    def _load_db(self):
        # version_nodes is temporarily unused
        self.path_nodes, self.version_nodes, self.all_versions = \
            DifferencesTables.loadTables(Configuration.getDbPath(self.app_name, self.plugin_name), printStats=False)


class WebAppGuesser(object):

    def __init__(self, url, logger=FileLogger(Configuration.DEFAULT_LOGFILE)):
        self.url = url
        self.logger = logger
        self.error_page_fingerprint = None
        self.already_checked_for_error_page = False
        self._host_down_errors = 0

    def guess_apps(self, app_list=None):
        """Probe a small number of indicator files for each supported webapp to 
        quickly check for existence, but not version.
        """
        possible_apps = []
        if not self.error_page_fingerprint and not self.already_checked_for_error_page:
            self.error_page_fingerprint = FingerprintUtils.identify_error_page(self.url)
            self.already_checked_for_error_page = True

        if not app_list:
            app_list = list(Configuration.APP_CONFIG.keys())

        for app in app_list:
            if self.guess_app(app):
                possible_apps.append(app)
            if self._host_down_errors >= HOST_DOWN_THRESHOLD:
                break
        return possible_apps

    def guess_app(self, app_name):
        """Probe a small number of paths to verify the existence (but not the 
        version) of a particular app
        """
        if not self.error_page_fingerprint and not self.already_checked_for_error_page:
            print("WARN: Fetching error page because it was not available")
            self.error_page_fingerprint = FingerprintUtils.identify_error_page(self.url)
            self.already_checked_for_error_page = True
        path_nodes, version_nodes, all_versions = DifferencesTables.loadTables(Configuration.getDbPath(app_name),
                                                                               printStats=False)

        return any(self.fingerprint_file(file, path_nodes, version_nodes, all_versions) for file
                   in Configuration.APP_CONFIG[app_name]["indicatorFiles"])

    def fingerprint_file(self, path, path_nodes, version_nodes, all_versions):
        """Fingerprint a single file given the path, and return a list
        possible versions implied by the result, or None if no information
        could be gleaned.
        """
        try:
            url = self.url + (path if path.startswith("/") else f"/{path}")
            data = FingerprintUtils.url_read_spoof_ua(url)
            self._host_down_errors = 0
            digest_hash = hashlib.md5(f"{data}{path}".encode('utf-8')).hexdigest()
            if digest_hash in path_nodes:
                possible_vers = path_nodes[path][digest_hash]
                self.logger.logFileHit(path, possible_vers, None, None, False)
                return possible_vers
            else:
                ms = FileMassagers.MASSAGERS
                for i in range(1, len(ms) + 1):
                    for massagersTpl in itertools.combinations(ms, i):
                        massagedData = data
                        for m in massagersTpl:
                            massagedData = m(massagedData)
                        massaged_hash = hashlib.md5(f"{massagedData}{path}".encode('utf-8')).hexdigest()
                        if massaged_hash in path_nodes[path]:
                            possible_vers = path_nodes[path][massaged_hash]
                            return possible_vers
                if FingerprintUtils.compare_to_error_page(self.error_page_fingerprint, data):
                    return None
                if not hasattr(path_nodes[path], digest_hash):
                    raise KeyError
        except (IOError, HTTPException) as e:
            if hasattr(e, 'reason'):
                self._host_down_errors += 1
        except KeyError:
            pass
        return None


class PluginGuesser(object):
    """Class that uses a BlindElephant fingerprint db to discover if a plugin or
    are installed in a web app.
    """

    def __init__(self, url, app_name, logger=FileLogger()):
        """Url should be the base url for the app (finding the plugin 
        directory is handled internally). App_name is required; it
        doesn't make sense to look for plugins if the app is unknown. 
        """
        self.error_page_fingerprint = None
        self.app_name = app_name
        self.url = url + Configuration.APP_CONFIG[app_name]["pluginsRoot"]
        self.logger = logger

    def guess_plugin(self, plugin_name):
        """Check for the existence of the named plugin"""
        path_nodes, version_nodes, all_versions = DifferencesTables.loadTables(
            Configuration.getDbPath(self.app_name, plugin_name), False)
        self.error_page_fingerprint = FingerprintUtils.identify_error_page(self.url)

        for file in FingerprintUtils.pick_indicator_files(version_nodes, all_versions):
            try:
                # TODO: factor out construction of path to plugin files...
                # not all plugin dirs can be found simple appending
                url = self.url + plugin_name + file
                # self.logger.logExtraInfo("    Trying " + url + "...")
                data = FingerprintUtils.url_read_spoof_ua(url)
                # Check for custom 404
                return not FingerprintUtils.compare_to_error_page(self.error_page_fingerprint, data)
            except urllib.error.URLError as e:
                # self.logger.logExtraInfo("URLError: %s" % e)
                pass
            except HTTPException as e2:
                # self.logger.logExtraInfo("HTTPError: %s" % e2)
                pass
        return False

    def guess_plugins(self):
        """For the given app, check for the existence any known plugins, and
        return a list possible plugins. Obviously if the named app doesn't 
        exist, plugins probably won't exist"""
        possible_plugins = []
        plugins_dir = Configuration.getDbDir(self.app_name)
        if os.access(plugins_dir, os.F_OK):
            for plugin_name in [x for x in sorted(os.listdir(plugins_dir)) if x.endswith(Configuration.DB_EXTENSION)]:
                plugin_name = plugin_name[:-len(Configuration.DB_EXTENSION)]
                if self.guess_plugin(plugin_name):
                    possible_plugins.append(plugin_name)
        possible_plugins.sort()
        self.logger.logExtraInfo(f"Possible plugins: {possible_plugins}")
        return possible_plugins
