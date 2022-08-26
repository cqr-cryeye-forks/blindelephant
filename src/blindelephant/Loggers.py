import sys


class FileLogger(object):
    def __init__(self, file=sys.stdout):
        self.app_name = None
        self.url = None
        self.file = file

    def logLoadDB(self, filename, all_versions, path_nodes, version_nodes):
        print(f"Loaded {filename} with {len(all_versions)} versions, "
              f"{len(path_nodes)} differentiating paths, and {len(version_nodes)} version groups.", file=self.file)

    def logFileHit(self, path, versions, massagers, error, nomatch):
        print("Hit", self.url + path, file=self.file)
        if nomatch:
            print("File produced no match. Error:", error, "\n", file=self.file)
        else:
            print("Possible versions based on result: %s\n" % (", ".join([v.vstring for v in sorted(versions)])),
                  file=self.file)

    def logStartFingerprint(self, url, app_name):
        self.url = url
        self.app_name = app_name
        print("Starting BlindElephant fingerprint for version of", app_name, "at", url, "\n", file=self.file)

    def logFinishFingerprint(self, versions, best_guess):
        print("", file=self.file)
        if versions:
            print("Fingerprinting resulted in:", file=self.file)
            for ver in versions:
                print(ver.vstring, file=self.file)
            print("\n\nBest Guess:", best_guess.vstring, file=self.file)
        else:
            print("Error: All versions ruled out!", file=self.file)

    def logExtraInfo(self, message):
        print(message, file=self.file)
