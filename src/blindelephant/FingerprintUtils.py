import operator
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from distutils.version import LooseVersion
from functools import reduce
from http.client import HTTPException

# TODO:
# - Unit tests for everything in this module

# How close a page needs to be to the reference error page in order to be considered a custom error page
# Range (0,1), with 1 being "exact match" between fingerprinted values
ERROR_PAGE_SIMILARITY_TOLERANCE = .9

TIMEOUT = 5
socket.setdefaulttimeout(TIMEOUT)


def fingerprint_error_page(page_data):
    """Takes page_data as a string and returns an "error page fingerprint".
    (This error page "fingerprint" is different from the hash-based fingerprints
    used in the rest of BlindElephant.)
     
    (Implementation detail: It's a list (one entry per page type) containing dicts of tags
    that we care about and their counts)
    """
    error_page_fingerprint = {"</div>": 0, "</a>": 0, "</tr>": 0, "</p>": 0}
    page_data = str(page_data)
    for tag in error_page_fingerprint:
        count = page_data.count(tag) + page_data.count(tag.upper())
        error_page_fingerprint[tag] = count

    return error_page_fingerprint


def identify_error_page(base_url):
    """Fetches pages that should not exist on the host and looks for 
    characteristics that would help us identify custom error pages (HTTP 200 w/ 
    error text instead of 404).
    
    If not identified, custom error pages can be mistaken for 
    present-but-no-match hashes and screw up guessing and fingerprinting.
    
    Returns an "error page fingerprint" that can be passed to compare_to_error_page()
    See fingerprint_error_page()
    """
    retry = 2
    while retry:
        try:
            url = f"{base_url}/should/not/exist.html"
            data = url_read_spoof_ua(url)
            error_page_fingerprint = [fingerprint_error_page(data)]
            url = f"{base_url}/should/not/exist.gif"
            data = url_read_spoof_ua(url)
            error_page_fingerprint.append(fingerprint_error_page(data))
            return error_page_fingerprint
        except IOError as e:
            if hasattr(e, 'code'):
                return None
            else:
                retry -= 1
        except HTTPException:
            retry -= 1
    return None


def compare_to_error_page(error_page_fingerprint, page_data):
    """Check a page returned from a server against an error_page_fingerprint and 
    return True if the page is probably a custom error page, or False if not. 
    
    See identify_error_page()
    """
    # print "Checking page against error page"
    if not error_page_fingerprint:
        # print "Returning false because of no error page fingerprint"
        return False

    candidate_fingerprint = fingerprint_error_page(page_data)
    # print "Error page fingerprint:", error_page_fingerprint
    # print "Candidate fingerprint:", candidate_fingerprint
    # Parked domains respond with random stuff; doing manual exceptions for now until a pattern emerges
    parking_phrases = ["GoDaddy.com is the world's No. 1 ICANN-accredited domain name registrar",
                       "This site is not currently available."]
    for phrase in parking_phrases:
        if phrase in page_data:
            # print "Identified custom 404 because of phrase:", phrase
            return True

    for page_type in error_page_fingerprint:
        for tag in page_type:
            tag_count_diff = abs(page_type[tag] - candidate_fingerprint[tag])
            bigger_count = max(page_type[tag], candidate_fingerprint[tag])
            tolerance = (bigger_count - (bigger_count * ERROR_PAGE_SIMILARITY_TOLERANCE))
            # print "Tag: %s\tErrPg: %d\tCandidate: %d" % (tag, error_page_fingerprint[tag], candidate_fingerprint[tag])
            # if a single value exceeds tolerance, we're done
            if tag_count_diff > tolerance:
                return False
    return True


def collapse_version_possibilities(possible_vers):
    """Take a list of version lists and return the intersection set or [] if 
    it's empty
    """
    ver_sets = [set(v) for v in [_f for _f in possible_vers if _f]]
    try:
        ver_set = reduce(lambda a, b: a & b, ver_sets)
    except Exception:
        ver_set = []

    if possible_vers and not ver_set:
        ver_set = resolve_conflicting_data(possible_vers)
    return ver_set


def get_version_map(ver_list):
    """Uses possible versions resulting from a fingerprint attempt and returns a dict that maps degenerate 
    versions their corresponding primary/strict version (if one was present in ver_list)
    or to itself otherwise (it won't make up versions that don't already exist).
    Eg:
        get_version_map([LooseVersion("1.3.4"), LooseVersion("1.3.4-RC2"), LooseVersion("1.3.5-beta1")])
        -> {LooseVersion("1.2.3-RC2") : LooseVersion("1.2.3"), 
            LooseVersion("1.3.5-beta1") : LooseVersion("1.3.5-beta1")}
    
    Useful for imposing a rough but consistent ordering or simplifying output
    """
    mapping = {}
    for ver in ver_list:
        match = re.match(r"([\d.]+)", ver.vstring)
        if match and match[0] and match[0] != ver:
            t_over = LooseVersion(match[0])
            mapping[ver] = t_over if t_over in ver_list else ver
        else:
            mapping[ver] = ver
    return mapping


def resolve_conflicting_data(possible_vers):
    """Takes a list of lists of vers and considers only the smallest list as valid data; returns that list.
    (There are of course other reasonable ways to resolve the conflict; this one was expedient.)
    """
    smallest = None
    for vers in possible_vers:
        if not smallest or len(vers) < len(smallest):
            smallest = vers
    return smallest


def pick_likely_version(ver_list):
    """Using possible versions from a fingerprint attempt, attempt to pick the latest. 
    See get_version_map
    """
    if not ver_list:
        return None
    ver_map = get_version_map(ver_list)
    simplified_ver_list = sorted([ver_map[ver] for ver in ver_list])
    return simplified_ver_list[-1]


def pick_fingerprint_files(path_nodes, all_versions):
    """Examine all known paths and return a list (of all paths) ordered by 
    their ability to give us lots of information about the installation.
    This is important since we only want to fetch paths that are present in 
    lots of versions, *and* we want there to be a lot of changes in the hash
    between versions
    
    This uses a fitness function that can be tweaked over time; right now 
    it's just a rough "best guess" about the value of fetching each path... 
        
    Future work is to take into account the versions reported on and try to achieve
    set coverage with minimal files.
    
    Returns an ordered list of paths.
    """
    # find a path with the best fitness
    candidate_nodes = []

    for path in list(path_nodes.keys()):
        curr_vers = []
        curr_hashes = len(path_nodes[path])

        for path_hash in path_nodes[path]:
            curr_vers.extend(path_nodes[path][path_hash])

        fitness = (float(len(curr_vers)) / float(len(all_versions))) + curr_hashes
        candidate_nodes.append({"fitness": fitness, "path": path})

    candidate_nodes.sort(key=operator.itemgetter('fitness'), reverse=True)
    return [f["path"] for f in candidate_nodes]


def pick_indicator_files(version_nodes, all_versions):
    """Choose a small number of files that (should) reliably indicate
    whether an app or plugin exists. Returns an ordered list of paths."""
    # TODO: this whole method is kind of fuzzy/best guess and ends up returning
    # some plugins w/ 2 files and others with 6. Could be more efficient
    # and predictable, but it's generic and does the job for now.
    nodes = []
    threshold = len(all_versions)

    # If we can find a version node that represents every possible version for
    # the app/plugin we're looking at (aka contains a file that is present in 
    # every known version) then that's the ideal choice, so start with that: 
    # threshold = len(all_versions).
    # Realistically there won't be a single file that accomplishes that, so we
    # lower the threshold until we find at least two different groups of 
    # files. That seems to be the sweet spot. TODO: More testing on that.
    while len(nodes) < 2 and threshold > 0:
        # try some numbers close to the total number of versions, backing off
        # until vers isn't empty
        nodes = [k for k in list(version_nodes.keys()) if len(k.split(",")) >= threshold]
        threshold -= 1

    indicator_files = []
    for ver in nodes:
        indicator_files.extend(n[0] for n in version_nodes[ver][:2])
    return list(set(indicator_files))


def url_read_spoof_ua(url):
    """I really hate to do this, but various spam, advertising and domain parking sites
    won't give either a 404 or a consistent landing page without pretending like we're a browser.
    """
    headers = {"User-agent": "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.3) "
                             "Gecko/20100423 Ubuntu/10.04 (lucid) Firefox/3.6.3"}
    req = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(req, timeout=TIMEOUT).read().decode()


def pick_winnow_files(possible_ver_list, version_nodes, max_paths):
    """Given a condensed ver list (and version nodes), return paths (up to max_paths) 
    that may be able to rule out of some versions.
    """
    # TODO: This is a not an efficient way of picking files, but it gives some improvement.
    # Changes to the keying and contents of version_nodes are probably the best way to significantly improve winnowing
    winnow_paths = []
    selected_version_groups = []
    for ver in possible_ver_list:
        print(f"for ver: {ver}  len winnow_paths: {len(winnow_paths)}\tmax_paths: {max_paths}")

        for ver_group in version_nodes:
            # print "  for ver_group:", ver_group
            if ver.vstring in ver_group and len(ver_group.split(",")) < len(
                    possible_ver_list) and ver_group not in selected_version_groups:
                winnow_paths.append(version_nodes[ver_group][0][0])
            if len(winnow_paths) >= max_paths:
                # print "returning winnow paths"
                return winnow_paths
    # print "returning winnow paths 2"
    return winnow_paths
