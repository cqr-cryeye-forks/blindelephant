"""Functions to create and access BlindElephant fingerprinting dbs"""
import hashlib
import os
import pickle
import re
import sys
from distutils.version import LooseVersion
from os.path import join, isdir

DEBUG = True

LooseVersion.__hash__ = lambda s: s.vstring.__hash__()

# Used by loadTable for caching
__loaded_tables = {}


# TODO: - emit in a format usable by other services - Correctly use the absence of a file for inference - use
#  something besides or in addition to MD5 that will survive small changes to the files. -- "Hashing Schmes for
#  Comparing and Synchronizing Distributed and Imperfectly Duplicated Data", Azriel and Bercovier,
#  http://leibniz.cs.huji.ac.il/tr/acc/2003/HUJI-CSE-LTR-2003-86_leibnitz.ps -- Some sort of nearest neighbor via
#  hamming distance type thing? -- (consider best Bin First http://en.wikipedia.org/wiki/Best_Bin_First,
#  semantic hashing, or spectral hashing) -- Context Triggered Piecewise Hashing (CTPH) ? (Utilizing Entropy to
#  Identify Undetected Malware, http://media.govtech.net/Digital_Communities/Guidance_Software
#  /Entropy_Near_Match_Analyzer_Whitepaper_w_use_cases.pdf) -- http://ssdeep.sourceforge.net/ -- rolling hash? --
#  file massagers (sorta...ugly, hacky approach)? - compute a table to seach for files that differentiate subsets of
#  a version set (mult-version winnowing)


def computeTables(basepath, versionDirectoryRegex="", directoryExcludeRegex="", fileExcludeRegex=""):
    """
    Walks version directories (any dirs in basepath matching versionDirectoryRegex) and computes hashes of all files,
    then uses those hashes to create and return pathNodes and versionNodes as a tuple: (pathNodes, versionNodes,
    versions)
    
    basepath is the root of the unpacked app (equivalent to the app root that the front end of the scanner will be
    pointed at) versionDirectoryRegex should have exactly one group, which should capture the version number to be
    used for hashing and reporting directoryExcludeRegex and fileExcludeRegex are used to drop items that should not
    be used for fingerprinting (because they're not usually readable, often changed/not reliable, whatever)
    
    pathNodes is a dictionary indexed by path and contains a dictionary of hashes (of the file+path) to a list of
    LooseVersions implied by that hash Eg: /help/screen.modadmin.edit.quickicons.html
    #index 04420e7034f67db9b9bfb020cf4bb6de ['1.0.14', '1.0.15']             #this hash implies one of these versions
    89266101ac7f4872a24b1188001b5f81 ['1.0.12', '1.0.13', '1.0.14']   #this hash implies one of these versions


    versionNodes is a dictionary indexed by an ordered, comma seperated string of version numbers; that index
    location contains the a list of (path, hash) tuples that can be used to assert (or refute) those versions
    Eg:
    1.5.3,1.5.4,1.5.5,1.5.6,1.5.7,1.5.8,1.5.9,1.5.10,1.5.11,1.5.12,1.5.14               #index
         ('/templates/system/css/general.css', '04ec769eecea814d71ea1e938c89099f')      #this file can be used to
         confirm/eliminate any of these versions
    
    1.0.8,1.0.9                                                                         #index
         ('htaccess.txt', '878876dcab630d5d165b0ac4a91fac6f')                           #this file can be used to
         confirm/eliminate any of these versions
    
    1.5.15
         ('/plugins/editors/tinymce/jscripts/tiny_mce/plugins/_template/langs/en.js',
         '207ed909925718f792cae256cbddca3c')
         ('/plugins/editors/tinymce/jscripts/tiny_mce/plugins/paste/editor_plugin_src.js',
         'a89780a5e042e29af32c3d886578524a')

    versions is a list of LooseVersions indicating all known versions    
    """

    # hashNodes is the simple hash that gives rise to versionNodes and pathNodes.
    # It is indexed by hash(data + path) and contains
    # a list of (version, path, hash) tuples
    hashNodes = {}
    pathNodes = {}
    versionNodes = {}
    versions = []
    numfiles = 0

    # root dirs for various versions of an app
    appdirs = [f for f in os.listdir(basepath) if isdir(join(basepath, f)) and re.match(versionDirectoryRegex, f)]

    # Process all version directories
    for app_dir in appdirs:
        # TODO: just a single regex isn't sufficiently expressive to capture all
        #  the random version naming schemes out there
        # See SPIP and phpMyAdmin
        # Suggest using a callable function that takes an app dir and returns a version version object
        version = LooseVersion(re.match(versionDirectoryRegex, app_dir)[1])
        versions.append(version)
        for root, dirs, files in os.walk(join(basepath, app_dir)):

            # print "files before:", files
            files = [d for d in files if not re.match(fileExcludeRegex, d)]
            # print "files after:", files

            to_remove = [_dir for _dir in dirs if re.match(directoryExcludeRegex, _dir)]
            for _dir in to_remove:
                dirs.remove(_dir)

            # compute hashes for all files
            for name in files:
                numfiles += 1
                # set path to be only the part of the full path *after* the version directory, eg /templates/system/css/general.css, not .../Joomla-x.y.z/templates/system/css/general.css
                path = join(root, name)
                path = path[path.index(app_dir) + len(app_dir):]
                # print "Path: ", path, "(root=", root, ", appdir=", appdir, ", name=", name,")"
                with open(join(root, name)) as file:
                    _hash = hashlib.md5(f"{file.read()}{path}".encode('utf-8')).hexdigest()

                # print version,join(root, name).replace(dir + "/", "", 1), hashlib.md5(open(join(root, name)).read()).hexdigest()
                node = (version, path, _hash)

                if _hash in hashNodes:
                    hashNodes[_hash].append(node)
                else:
                    hashNodes[_hash] = [node]

                if path in pathNodes:
                    if _hash in pathNodes[path]:
                        pathNodes[path][_hash].append(version)
                    else:
                        pathNodes[path][_hash] = [version]
                else:
                    pathNodes[path] = {_hash: [version]}
                    # print "Intermediate result: Processed %s versions with %s files matching filter, resulting in %s unique hashes, %s differentiating paths" % (len(versions), numfiles, len(hashNodes), len(pathNodes))
                    # print "%s, %s, %s, %s" % (len(versions), numfiles, len(hashNodes), len(pathNodes))

    for key in list(hashNodes.keys()):
        # collect versions implied by this file+path hash, and construct an ordered versions str to use as key
        # TODO add assert that all path and hash are equal for collected versions; definitely an error if they're ever the same
        verlist = sorted([version for (version, path, _hash) in hashNodes[key]])
        verlist = [version.vstring for version in verlist]
        verliststr = ",".join(verlist)
        # print verliststr, hashNodes[key]

        # populate versionNodes for this ordered combination of versions (storing path and hash of first node since they should all be the same)
        if verliststr in versionNodes:
            versionNodes[verliststr].append((hashNodes[key][0][1], hashNodes[key][0][2]))
        else:
            versionNodes[verliststr] = [(hashNodes[key][0][1], hashNodes[key][0][2])]

    if DEBUG:
        print(f"Processed {len(versions)} versions with {numfiles} files matching filter, "
              f"resulting in {len(hashNodes)} unique hashes, {len(pathNodes)} differentiating paths, "
              f"and {len(versionNodes)} version groups.")

        # f = open("tmptable.txt", "w")
        # f.write("Path Nodes\n==============================\n")
        # f.write(prettyPathNodes(pathNodes))
        # f.write("\n\n\n\n")
        # f.write("Version Nodes\n==============================\n")
        # f.write(prettyVersionNodes(versionNodes))
        # f.write("\n\n\n\n")
        # f.write("Hash Nodes\n==============================\n")
        # for key in hashNodes:
        #    f.write("\n\n"+key+"\n")
        #    for node in hashNodes[key]:
        #        f.write("    " + str(node) + "\n")
        # f.close()

    versions.sort()
    return pathNodes, versionNodes, versions


def saveTables(filename, pathNodes, versionNodes, versions):
    """Save the results of computeTables to disk.
    """
    with open(filename, "wb") as f:
        pickle.dump((pathNodes, versionNodes, versions), f, -1)


def loadTables(filename, printStats=True, useCaching=True):
    """Load a file created with saveTables(...) and return pathNodes, versionNodes and all_versions as a
    tuple. See computeTables for the structure of each tuple element.
    
    Attempts to do some caching to reduce in-memory footpring; threads should 
    not modify structures returned from a request with useCaching turned on 
    (the default).
    """
    if filename in __loaded_tables and useCaching:
        pathNodes, versionNodes, versions = __loaded_tables[filename]
    else:
        with open(filename, "rb") as f:
            pathNodes, versionNodes, versions = pickle.load(f)
        __loaded_tables[filename] = pathNodes, versionNodes, versions
    if printStats:
        print(f"Loaded {filename} with {len(versions)} versions, {len(pathNodes)} differentiating paths, "
              f"and {len(versionNodes)} version groups.")

    return pathNodes, versionNodes, versions


def prettyVersionNode(versionNode):
    return "".join(f"\t{str(path)}" + "\n" for path in versionNode)


def prettyPathNode(pathNode):
    return "".join("    %s %s\n" % (_hash, [v.vstring for v in sorted(pathNode[_hash])]) for _hash in pathNode)


def prettyVersionNodes(versionNodes):
    ret = ""
    for key in list(versionNodes.keys()):
        ret += "\n\n" + key + "\n"
        ret += prettyVersionNode(versionNodes[key]) + "\n"
    return ret


def prettyPathNodes(pathNodes):
    ret = ""
    for path in list(pathNodes.keys()):
        ret += "\n\n" + path + "\n"
        ret += prettyPathNode(pathNodes[path]) + "\n"
    return ret


def verListStr(verlist):
    return ",".join([v.vstring for v in sorted(verlist)])


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage:", sys.argv[0], "<basepath> <versionDirectoryRegex> <directoryExcludeRegex> <fileExcludeRegex>")
        print(
            "Walks all dirs at path that match version directory and computes sets of differences, pruning directories that match directoryExcludeRegex and files that match fileExcludeRegex")
        quit(0)
    computeTables(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
