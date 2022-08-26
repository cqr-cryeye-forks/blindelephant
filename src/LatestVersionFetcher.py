import os
import re
import time
import urllib.error
import urllib.error
import urllib.parse
import urllib.parse
import urllib.request
import urllib.request
from optparse import OptionParser

from bs4 import BeautifulSoup

import blindelephant.Configuration as Config
import blindelephant.DifferencesTables as DiffTables


# ====================================================
# This file grabs the latest releases of supported webapps and copies them to the downloads dir of each webapp
# It should usually be run via cron job
# ====================================================

# TODO:
# - Refactor to do away with the idea of the strainer; just call fetcher with a list of filename and
# dl locations
# - Sometimes zips come down empty (eg latest version of some wordpress plugins) -- detect
# and reject these bogus new versions

# the soup strainer here isn't exactly what's described in the BeautifulSoup documentation
# soupStrainerFunc is expected to consume a beautifulSoup object and produce a list of
# {'href': ..., 'filename': ...} objects
# representing all the currently available versions... some strainers load additional pages
# in order to collect links (eg, mediawiki)
# downloads prefix should be provided if strained links are relative, can be omitted if absolute
def _fetch_template(appName, releasesUrl, soupStrainerFunc, downloadsPrefix="", plugin=None):
    plugins = f"-plugins/{plugin}" if plugin else ""
    knownFiles = os.listdir(f'{Config.APPS_PATH}{appName}{plugins}/downloads')

    # print "Known:"
    # for file in sorted(knownFiles):
    #    print file
    # print "Fetching: ", releasesUrl
    f = urllib.request.urlopen(releasesUrl)
    soup = BeautifulSoup(f.read().decode())
    f.close()

    availableFiles = soupStrainerFunc(soup)
    # print "Available files:"
    # for f in availableFiles:
    #    print f

    newVersTemp = [f for f in availableFiles if f['filename'] not in knownFiles]

    # Some sites, notably sourceforge, offer the same download url twice.
    # Unify list so as not to re-download a file twice in one session
    # (just converting to set() won't work... dicts aren't hashable)
    newVers = []
    for v in newVersTemp:
        if v not in newVers:
            newVers.append(v)

    # print "New files:"
    # for f in availableFiles:
    #    print f

    for v in sorted(newVers):
        url = f"{downloadsPrefix}{v['href']}"
        # throttle to not abuse remote server
        time.sleep(1.5)
        # TODO: add a check that we're not re
        print("Attempting to fetch:", url)

        req = urllib.request.Request(url)
        try:
            f = urllib.request.urlopen(req)
            local_file_path = f'{Config.APPS_PATH}{appName}{plugins}/downloads/{v["filename"]}'
            with open(local_file_path, "wb") as local_file:
                local_file.write(f.read())
        except urllib.error.HTTPError as e:
            print("HTTP Error:", e.code, url)
        except urllib.error.URLError as e:
            print("URL Error:", e.reason, url)

    return [v['filename'] for v in newVers]


# Fetchers for currently supported apps not being released right now, sorry;
# I don't want to make it easy to abuse the mirrors.
# Contact me if you need them for some reason.

# example fetchers for new apps
def _example_strainer(soup):
    links = soup.findAll('a', attrs={'href': lambda s: s and s.endswith('.tar.gz')})
    return [{'href': link['href'], 'filename': link.string} for link in links]


def fetch_example():
    return _fetch_template('appname', "http://example.com/releases", _example_strainer, "")


def update_dbs(apps):
    """Used to create .pkl files for any apps or declared plugins
    supported but don't have an up-to-date pkl file. 
    Takes a list of app names.
    """
    for app in apps:
        if not os.access(Config.getDbPath(app), os.F_OK):
            print(f"No db file available for app {app}. Creating it from {Config.getAppPath(app)}...")

            pathNodes, versionNodes, all_versions = DiffTables.computeTables(
                Config.getAppPath(app),
                Config.APP_CONFIG[app]["versionDirectoryRegex"],
                Config.APP_CONFIG[app]["directoryExcludeRegex"],
                Config.APP_CONFIG[app]["fileExcludeRegex"])

            DiffTables.saveTables(Config.getDbPath(app), pathNodes, versionNodes, all_versions)
        else:
            print(f"Found db file for app {app}", end=' ')
            pathNodes, versionNodes, all_versions = DiffTables.loadTables(Config.getDbPath(app), False)

            versInDb = len(all_versions)
            versOnDisk = len([entry for entry in os.listdir(Config.getAppPath(app))
                              if re.match(Config.APP_CONFIG[app]["versionDirectoryRegex"], entry)])

            if versInDb != versOnDisk:
                print(f"but it is out of date ({versInDb} versions in db, {versOnDisk} versions on disk). "
                      f"Recreating it from {Config.getAppPath(app)}... ")

                pathNodes, versionNodes, all_versions = DiffTables.computeTables(
                    Config.getAppPath(app),
                    Config.APP_CONFIG[app]["versionDirectoryRegex"],
                    Config.APP_CONFIG[app]["directoryExcludeRegex"],
                    Config.APP_CONFIG[app]["fileExcludeRegex"])

                DiffTables.saveTables(Config.getDbPath(app), pathNodes, versionNodes, all_versions)
            else:
                print(".")
        if os.access(Config.getAppPluginPath(app), os.F_OK):
            for plugin in [p for p in sorted(os.listdir(Config.getAppPluginPath(app)))
                           if os.path.isdir(Config.getAppPluginPath(app, p))]:
                if not os.access(Config.getDbPath(app, plugin), os.F_OK):
                    print(f"No db file available for {app} plugin {plugin}. "
                          f"Creating it from {Config.getAppPluginPath(app, plugin)}...")

                    pathNodes, versionNodes, all_versions = DiffTables.computeTables(
                        Config.getAppPluginPath(app, plugin),
                        (plugin + Config.APP_CONFIG[app]["pluginsDirectoryRegex"]),
                        "none",
                        Config.APP_CONFIG[app]["fileExcludeRegex"])

                    DiffTables.saveTables(Config.getDbPath(app, plugin), pathNodes, versionNodes, all_versions)

                else:
                    print(f"Found db file for {app} plugin {plugin}", end=' ')
                    pathNodes, versionNodes, all_versions = DiffTables.loadTables(Config.getDbPath(app, plugin), False)

                    versInDb = len(all_versions)
                    versOnDisk = len([entry for entry in os.listdir(Config.getAppPluginPath(app, plugin))
                                      if re.match(plugin + Config.APP_CONFIG[app]["pluginsDirectoryRegex"], entry)])

                    if versInDb != versOnDisk:
                        print(f"but it is out of date ({versInDb} versions in db, {versOnDisk} versions on disk). "
                              f"Recreating it from {Config.getAppPluginPath(app, plugin)}... ")

                        pathNodes, versionNodes, all_versions = DiffTables.computeTables(
                            Config.getAppPluginPath(app, plugin),
                            (plugin + Config.APP_CONFIG[app]["pluginsDirectoryRegex"]),
                            Config.APP_CONFIG[app]["directoryExcludeRegex"],
                            Config.APP_CONFIG[app]["fileExcludeRegex"])

                        DiffTables.saveTables(Config.getDbPath(app, plugin), pathNodes, versionNodes, all_versions)

                    else:
                        print(".")


if __name__ == '__main__':

    USAGE = "usage: %prog [options] appName"
    EPILOGUE = "Download newly-available releases of supported WebApplications.\n" \
               "Use \"all\" as an app name to update all known."

    parser = OptionParser(usage=USAGE, epilog=EPILOGUE)
    parser.add_option("-p", "--plugins", action="store_true", help="Fetch all plugins for the given app")
    parser.add_option("-u", "--update_dbs", action="store_true", help="Update databases (developer use only)")

    (options, args) = parser.parse_args()

    if options.update_dbs:
        if len(args) < 1 or args[0] == "all":
            args = list(Config.APP_CONFIG.keys())
        print(args)
        update_dbs(args)
        quit()

    if len(args) < 1:
        print("Error: AppName is required\n")
        parser.print_help()
        quit()

    if args[0] == "all":
        for func in [s for s in sorted(globals().keys()) if s.startswith("fetch")]:
            print(func)
            time.sleep(2)
            print(globals()[func]())
    elif f"fetch{args[0]}" in globals():
        print("Checking for new versions of", args[0])
        print(globals()[f"fetch{args[0]}"]())
        if options.plugins:
            print("Checking for new versions of", args[0], "plugins")
            eval(f"fetch{args[0]}plugins()")

    else:
        print(f"Error: {args[0]}" + " is not supported for fetching latest versions (do it manually or add it here)\n")

        parser.print_help()
        quit()
