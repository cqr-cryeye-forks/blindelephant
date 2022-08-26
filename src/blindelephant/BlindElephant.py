#!/usr/bin/python
import os
from optparse import OptionParser

from src.blindelephant import Configuration, Fingerprinters

if __name__ == '__main__':

    USAGE = "usage: %prog [options] url appName"
    EPILOGUE = """Use \"guess\" as app or plugin name to attempt to
                  discover which supported apps/plugins are installed."""

    parser = OptionParser(usage=USAGE, epilog=EPILOGUE)
    parser.add_option("-p", "--pluginName",
                      help="Fingerprint version of plugin (should apply to web app given in appname)")
    parser.add_option("-s", "--skip", action="store_true", help="Skip fingerprinting webpp, just fingerprint plugin")
    parser.add_option("-n", "--numProbes", type='int',
                      help="Number of files to fetch (more may increase accuracy). Default: %default", default=15)
    parser.add_option("-w", "--winnow", action="store_true",
                      help="If more than one version are returned, use winnowing to attempt to narrow it down (up to numProbes additional requests).")
    parser.add_option("-l", "--list", action="store_true", help="List supported webapps and plugins")
    parser.add_option("-u", "--updateDB", action="store_true",
                      help="Pull latest DB files from blindelephant.sourceforge.net repo (Equivalent to svn update on blindelephant/dbs/). May require root if blindelephant was installed with root.")

    (options, args) = parser.parse_args()

    if options.list:
        print("Currently configured web apps:", len(list(Configuration.APP_CONFIG.keys())),
              file=Configuration.DEFAULT_LOGFILE)
        for app in sorted(Configuration.APP_CONFIG.keys()):
            pluginsDir = Configuration.getDbDir(app)
            plugins = os.listdir(pluginsDir) if os.access(pluginsDir, os.F_OK) else []
            plugins = [p for p in plugins if p.endswith(Configuration.DB_EXTENSION)]
            print("%s with %d plugins" % (app, len(plugins)), file=Configuration.DEFAULT_LOGFILE)
            for p in sorted(plugins):
                print(" -", p[:-(len(Configuration.DB_EXTENSION))], file=Configuration.DEFAULT_LOGFILE)
        quit()

    if options.updateDB:
        """Added at the request of backbox.org; pretty hacky. May formalize this in the future if there's demand"""
        import tempfile
        import urllib.request
        import urllib.parse
        import urllib.error
        import os
        import tarfile

        dbtar_url = "http://blindelephant.svn.sourceforge.net/viewvc/blindelephant/trunk/src/blindelephant/dbs/?view=tar"
        untar_dir = os.path.join(Configuration.getDbDir(), os.path.pardir)  # so that dbs/ in tar overlays existing dbs/

        tmp = tempfile.NamedTemporaryFile()
        print("Fetching latest DB files from", dbtar_url, file=Configuration.DEFAULT_LOGFILE)
        urllib.request.urlretrieve(
            "http://blindelephant.svn.sourceforge.net/viewvc/blindelephant/trunk/src/blindelephant/dbs/?view=tar",
            tmp.name)
        f = tarfile.open(tmp.name)
        print("Extracting to ", untar_dir, file=Configuration.DEFAULT_LOGFILE)
        f.extractall(untar_dir)
        tmp.close()
        quit()

    if len(args) < 2:
        print("Error: url and appName are required arguments unless using -l, -u, or -h\n",
              file=Configuration.DEFAULT_LOGFILE)
        parser.print_help()
        quit()

    url = args[0].strip("/")
    if not (url.startswith("http://") or url.startswith("https://")):
        url = f"http://{url}"
    app_name = args[1]

    if app_name == "guess":
        g = Fingerprinters.WebAppGuesser(url)
        print("Probing...", file=Configuration.DEFAULT_LOGFILE)
        apps = g.guess_apps()
        print("Possible apps:", file=Configuration.DEFAULT_LOGFILE)
        for app in apps:
            print(app, file=Configuration.DEFAULT_LOGFILE)
    elif app_name not in Configuration.APP_CONFIG:
        print("Unsupported web app \"" + app_name + "\"", file=Configuration.DEFAULT_LOGFILE)
        quit()
    elif not options.skip:
        fp = Fingerprinters.WebAppFingerprinter(url, app_name, num_probes=options.numProbes, winnow=options.winnow)
        fp.fingerprint()

    if options.pluginName == 'guess':
        if not options.skip:
            print("\n\n", file=Configuration.DEFAULT_LOGFILE)
        g = Fingerprinters.PluginGuesser(url, app_name)
        g.guess_plugins()
    elif options.pluginName:
        fp = Fingerprinters.PluginFingerprinter(url, app_name, options.pluginName, num_probes=options.numProbes)
        fp.fingerprint()
