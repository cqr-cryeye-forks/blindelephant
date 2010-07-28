#!/usr/bin/python
import Fingerprinters as wafp
import Configuration as wac

from optparse import OptionParser
import os

if __name__ == '__main__':

    USAGE = "usage: %prog [options] url appName"
    EPILOGUE = """Use \"guess\" as app or plugin name to attempt to attempt to
                  discover which supported apps/plugins are installed."""

    parser = OptionParser(usage=USAGE, epilog=EPILOGUE)
    parser.add_option("-p", "--pluginName", help="Fingerprint version of plugin (should apply to web app given in appname)")
    parser.add_option("-s", "--skip", action="store_true", help="Skip fingerprinting webpp, just fingerprint plugin")
    parser.add_option("-n", "--numProbes", type='int', help="Number of files to fetch (more may increase accuracy). Default: %default", default=15)
    parser.add_option("-w", "--winnow", action="store_true", help="If more than one version are returned, use winnowing to attempt to narrow it down (up to numProbes additional requests).")
    parser.add_option("-l", "--list", action="store_true", help="List supported webapps and plugins")

    (options, args) = parser.parse_args()

    if options.list:
       print >> wac.DEFAULT_LOGFILE, "Currently configured web apps:", len(wac.APP_CONFIG.keys())
       for app in sorted(wac.APP_CONFIG.keys()):
           pluginsDir = wac.getDbDir(app)
           plugins = os.listdir(pluginsDir) if os.access(pluginsDir, os.F_OK) else []
           plugins = [p for p in plugins if p.endswith(wac.DB_EXTENSION)]
           print >> wac.DEFAULT_LOGFILE, "%s with %d plugins" % (app, len(plugins))
           for p in sorted(plugins):
               print >> wac.DEFAULT_LOGFILE, " -", p[:-(len(wac.DB_EXTENSION))]
       quit()
    
    if len(args) < 2:
        print >> wac.DEFAULT_LOGFILE, "Error: url and appName are required arguments unless using -l, -u, or -h\n"
        parser.print_help()
        quit()
    
    url = args[0].strip("/")
    if not url.startswith("http://"):
        url = "http://" + url
    app_name = args[1]

    if app_name == "guess":
        g = wafp.WebAppGuesser(url)
        print >> wac.DEFAULT_LOGFILE, "Probing..."
        apps = g.guess_apps()
        print >> wac.DEFAULT_LOGFILE, "Possible apps:"
        for app in apps:
            print >> wac.DEFAULT_LOGFILE, app
    elif not wac.APP_CONFIG.has_key(app_name):
        print >> wac.DEFAULT_LOGFILE, "Unsupported web app \""+app_name+"\""
        quit()
    elif wac.APP_CONFIG.has_key(app_name) and not options.skip:
        fp = wafp.WebAppFingerprinter(url, app_name, num_probes=options.numProbes, winnow=options.winnow)
        fp.fingerprint()
    
    if options.pluginName == 'guess':
        if not options.skip:
            print >> wac.DEFAULT_LOGFILE, "\n\n"
        g = wafp.PluginGuesser(url, app_name)
        g.guess_plugins()
    elif options.pluginName:
        fp = wafp.PluginFingerprinter(url, app_name, options.pluginName, num_probes=options.numProbes)
        fp.fingerprint()
