# Get top resolvers.
# We want to characterize the resolvers.
# We can identify two classes: open resolvers, and resolvers that match the AS itself.
# We currently classify the other resolvers as "same country" and "others", but
# this misses at least three potential issues:
#
# - resolution performed in other ASES under the same management
# - resolution performed by user or organization selected resolvers hosted in the cloud
# - resolutions performed by a third party not yet identified as an open resolver.
#
# We have no idea of the size of each of those issues. We want to identify the main
# actors, so we are going to go over the transactions and:
#
# - look at the unique query ID per CC/AS, under the same rules as other studies.
# - filter out the queries handled by "self" or by "open resolver"
# - for the remaining queries, tabulate by resolver AS, and then by the
#   pair of query CC and query AS
# - save the result for each capture point in a file
#
# This gives us the first "raw data" file.
# Next step:
#
# - merge the results from multiple files
#
# This gives us the "all included" file.
#
# Then, with that file, perform detailed studies:
#
# - find the most important third party resolvers, e.g., those handling at
#   least 10,000 unique query ID
# - tabulate the number of CC/AS served, list the top 5, etc.
#

import sys
import os
from pathlib import Path
import ip2as
import rsv_log_parse
import traceback
import time
import pandas as pd
import bz2
import top_as

class resolver_cc_as:
    def __init__(self, query_AS, query_cc, AS_name="", has_name=False):
        self.query_AS = query_AS
        self.query_cc = query_cc
        self.AS_name = AS_name
        self.has_name = has_name
        self.uid_set = set()
        self.count = 0

    def add_uid(self, uid):
        if not uid in self.uid_set:
            self.uid_set.add(uid)
            self.count += 1

    def add_count(self, count):
        self.count += count

    
    def headers():
        return [ 
            'resolver_AS',
            'query_cc',
            'query_AS',
            'count'
           ]
    
    def cc_as_row(self, resolver_AS, as_names):
        return [ resolver_AS, self.query_cc, self.query_AS, self.count ]

    
    def top_headers():
        return [ 
            'resolver_AS',
            'query_cc',
            'query_AS',
            'count',
            'AS_name',
            'has_name'
           ]

    def top_cc_as_row(self, resolver_AS, as_names, AS_name="", has_name=False):
        if self.AS_name == "":
            self.AS_name = as_names.name(self.query_AS)
        return [ resolver_AS, self.query_cc, self.query_AS, self.count, self.AS_name, self.has_name ]


class resolver:
    def __init__(self, resolver_AS):
        self.resolver_AS = resolver_AS
        self.r_cc_AS = dict()
        self.total = 0
        self.tops = []

    def add_uid(self, query_AS, query_cc, uid, AS_name="", has_name=False):
        key = query_cc + query_AS
        if not key in self.r_cc_AS:
            self.r_cc_AS[key] = resolver_cc_as(query_AS, query_cc, AS_name=AS_name, has_name=has_name)
        self.r_cc_AS[key].add_uid(uid)

    def as_rows(self, as_names, AS_name="", has_name=False):
        t = []
        for key in self.r_cc_AS:
            t.append(self.r_cc_AS[key].cc_as_row(self.resolver_AS, as_names ))
        return t

    def load_row(self, query_cc, query_AS, count, AS_name="", has_name=False):
        if  isinstance(query_cc, str) and len(str(query_cc)) > 0 and \
            isinstance(query_AS, str) and len(str(query_AS)) > 0:
            key = query_cc + query_AS
            if not key in self.r_cc_AS:
                self.r_cc_AS[key] = resolver_cc_as(query_AS, query_cc, AS_name=AS_name, has_name=has_name)
            self.r_cc_AS[key].add_count(count)

    def compute_top(self):
        self.total = 0
        self.tops = []
        for key in self.r_cc_AS:
            rca = self.r_cc_AS[key]
            self.total += rca.count
            self.tops.append([key, rca.count])
        self.tops.sort(key=lambda x: x[1], reverse=True)

    def export_top(self, as_names, threshold=100):
        t = []
        resolver_cc = as_names.cc(self.resolver_AS)
        r_name = as_names.name(self.resolver_AS)
        t.append([ self.resolver_AS, resolver_cc, "total", self.total, r_name, False ])
        for x in self.tops:
            if x[1] < threshold:
                break
            t.append(self.r_cc_AS[x[0]].top_cc_as_row(self.resolver_AS, as_names))
        return t

class resolver_list:
    def __init__(self):
        self.resolvers = dict()
        self.top_list = []
        self.sum_total = 0
        self.groups = dict()

    def load(self, file_name, ip2a4, ip2a6, as_names, rr_types=[], experiment=[], log_threshold = 15625, time_start = 0):
        nb_events = 0
        lth = log_threshold

        filtering = len(rr_types) > 0 or len(experiment) > 0

        if file_name.endswith(".bz2"):
            F = bz2.open(file_name, "rt")
        else:
            F = open(file_name, "r")
        for line in F:
            parsed = True
            try:
                x = rsv_log_parse.rsv_log_line()
                parsed = x.parse_line(line)
            except Exception as exc:
                traceback.print_exc()
                print('\nCode generated an exception: %s' % (exc))
                print("Cannot parse:\n" + line + "\n")
                parsed = False
            if parsed:
                if (not filtering) or x.filter(rr_types=rr_types, experiment=experiment):
                    x.set_resolver_AS(ip2a4, ip2a6, as_names)
                    if x.resolver_AS != 'AS0' and (x.resolver_tag == 'Same_CC' or x.resolver_tag == 'Others'):
                        if not x.resolver_AS in self.resolvers:
                            self.resolvers[x.resolver_AS] = resolver(x.resolver_AS)
                        self.resolvers[x.resolver_AS].add_uid(x.query_AS, x.query_cc, x.query_user_id)
                    nb_events += 1
                    if (nb_events%lth) == 0:
                        print("loaded " + str(nb_events) + " events at " + str(time.time() - time_start))
                        lth *= 2
        return nb_events

    def export_df(self, as_names):
        r = []
        for resolver_AS in self.resolvers:
            r += self.resolvers[resolver_AS].as_rows(as_names)
        df = pd.DataFrame(r, columns=resolver_cc_as.headers())
        return df

    def process_row(self, x):
        resolver_AS = x['resolver_AS']
        #AS_name = ""
        #has_name = False
        #if 'AS_name' in x:
        #    AS_name = x['AS_name']
        #if 'has_name' in x:
        #    has_name = x['has_name']
        if not resolver_AS in self.resolvers:
            self.resolvers[resolver_AS] = resolver(resolver_AS)
        self.resolvers[resolver_AS].load_row(x['query_cc'], x['query_AS'], x['count'])
        self.sum_total += x['count']

    def load_file(self, saved_file):
        df = pd.read_csv(saved_file)
        df.apply(lambda x: self.process_row(x), axis=1)

    def export_top(self, top_file, as_names, threshold=100):
        self.top_list = []
        for resolver_AS in self.resolvers:
            self.resolvers[resolver_AS].compute_top()
            self.top_list.append([ resolver_AS, self.resolvers[resolver_AS].total])
        self.top_list.sort(key=lambda x: x[1], reverse=True)
        print("Computed top list, len: " + str(len(self.top_list)))
        t = []
        for x in self.top_list:
            if x[1] < threshold:
                break
            t += self.resolvers[x[0]].export_top(as_names, threshold=int(threshold/10))
        df = pd.DataFrame(t, columns=resolver_cc_as.top_headers())
        df.to_csv(top_file, sep=',')

# rsv_classify
#
# Look at the resolvers/AS in the "top resolvers" file, and attempt to classify them
# in three parts:
#
# - probably cloud services
# - probably AS groups
# - not clear
# 
#
# example 1:
# 0,AS9498,IN,total,1545226,BBIL-AP,True
# 1,AS9498,IN,AS45609,1283286,BHARTI-MOBILITY-AS-AP,True
# 2,AS9498,IN,AS24560,258850,AIRTELBROADBAND-AS-AP,True
#
# The top data helps:
#
# 1,AP,IN,AS45609,BHARTI-MOBILITY-AS-AP,Cellular,1375613,TRUE
# 2,AP,IN,AS24560,AIRTELBROADBAND-AS-AP,Mix,292792,TRUE
# Computing fractions:
# 
# 0,AS9498,IN,total,1545226,BBIL-AP,True
# 1,AS9498,IN,AS45609,1283286,BHARTI-MOBILITY-AS-AP,True => 1283286/1375613 = 93%!
# 2,AS9498,IN,AS24560,258850,AIRTELBROADBAND-AS-AP,True => 258850/292792 = 88% !
#
# this clearly an ISP, with AS9498 serving a majority of the queries to AS45609 and AS24560.
# 
# example 2:
# But then, we have a reciprocal:
#
# 62,AS24560,IN,total,122391,AIRTELBROADBAND-AS-AP,True
# 63,AS24560,IN,AS45609,122064,BHARTI-MOBILITY-AS-AP,True
#
# which implies that AS24560 is serving 122064/1283286 of AS45609, i.e., 9.6%. That may
# mean that broadband users are sometime dual homes and using wireless DNS, or that
# the DNS requests are somehow load banlanced.
# 
# example 3:
# 8,AS396982,US,total,133388,GOOGLE-CLOUD-PLATFORM,True
# 9,AS396982,PK,AS59257,12365,CMPAKLIMITED-AS-AP,True
# 10,AS396982,PK,AS9541,11748,CYBERNET-AP,True
# 11,AS396982,PK,AS17557,5331,PKTELECOM-AS-PK,True
# 12,AS396982,IR,AS58224,5328,TCI,True
# 13,AS396982,AE,AS5384,5176,Emirates Telecommunications,True
# 14,AS396982,SO,AS37371,4480,Hormuud Telecom Somalia INC,True
# 15,AS396982,BH,AS51375,3194,VIVABH,True
# ...
# This clearly is a cloud service. The highest user is:
# AP,PK,AS59257,CMPAKLIMITED-AS-AP,Cellular,52089,TRUE
# 12365/52089 = 23.7%
#
# Example 4:
# 72,AS20940,EU,total,95879,AKAMAI-ASN1,True
# 73,AS20940,US,AS7922,8513,Comcast,True
# 74,AS20940,US,AS7018,5205,AT&T,True
# 75,AS20940,US,AS63949,4733,AKAMAI-LINODE-AP,True
# 76,AS20940,US,AS6167,2363,Verizon,True
# 77,AS20940,US,AS701,2212,Verizon Business (Fios),True
# 78,AS20940,US,AS20115,2130,Charter,True
# 79,AS20940,US,AS22773,1587,Cox,True
# ...
#
# The classifier uses a set of features:
#
# - sum of dependencies with > 10% of total versus total
# - sum of dependencies with > 1000 versus total
# - sum of dependencies with > 500 versus total
# - max of dependencies versus total
# - number of dependencies > 10% of total
# - number of dependencies > 1000
# - number of dependencies > 500
# - number of countries with > 10% of total
# - number of countries with > 1000
# - number of countries with > 500
# - number of dependencies with > 20% of dependent
# - number of dependencies with > 50% of dependent
#
# The first step is to do feature extraction.
# Then use manual annotation to get examples of clouds and ISP services
#


class top_resolver:
    def __init__(self, resolver_AS, resolver_cc, total, AS_name, has_name):
        self.top_list = []
        self.resolver_AS = resolver_AS
        self.resolver_cc = resolver_cc
        self.total = total
        self.AS_name = AS_name
        self.has_name = has_name

    def add_query_as(self, query_AS, query_cc, count, AS_name, has_name):
        cc_as = resolver_cc_as(query_AS, query_cc, AS_name=AS_name, has_name=has_name)
        cc_as.count = count
        self.top_list.append(cc_as)

    def get_names(self, know_names):
        all_found = True
        if not self.has_name:
            success, AS_name = know_names.get_name(self.resolver_AS, self.resolver_cc, self.AS_name)
            if success:
                self.AS_name = AS_name
                self.has_name = True
            else:
                all_found = False
        for cc_as in self.top_list:
            if not cc_as.has_name:
                success, AS_name = know_names.get_name(cc_as.query_AS, cc_as.query_cc, cc_as.AS_name)
                if success:
                    cc_as.AS_name = AS_name
                    cc_as.has_name = True
                else:
                    all_found = False
        return all_found

    def top_rows(self):
        t = []
        t.append([
            self.resolver_AS,
            self.resolver_cc,
            'total',
            self.total,
            self.AS_name,
            self.has_name])
        
        for cc_as in self.top_list:
            t.append([
                self.resolver_AS,
                cc_as.query_cc,
                cc_as.query_AS,
                cc_as.count,
                cc_as.AS_name,
                cc_as.has_name])
            
        return t
    
    # The classifier uses a set of features:
    #
    # - sum of dependencies with > 10% of total versus total
    # - sum of dependencies with > 1000 versus total
    # - sum of dependencies with > 500 versus total
    # - max of dependencies versus total
    # - number of dependencies > 10% of total
    # - number of dependencies > 1000
    # - number of dependencies > 500
    # - number of countries with > 10% of total
    # - number of countries with > 1000
    # - number of countries with > 500
    # - number of dependencies with > 20% of dependent
    # - number of dependencies with > 50% of dependent
    # - ratio of queries served vs queries served + native queries for AS
    # - total number of queries served. 
    def feature_headers():
        return [
            'resolver_AS',
            'p_10p',
            'p_1000',
            'p_500',
            'p_max_dep',
            'nb_10p',
            'nb_1000',
            'nb_500',
            'nb_cc_10p',
            'nb_cc_1000',
            'nb_cc_500',
            'nb_20pd',
            'nb_50pd',
            'ratio_3rdp',
            'total']
    def export_features(self, big_as_list):
        sum_10p = 0
        sum_1000 = 0
        sum_500 = 0
        max_dep = 0
        nb_10p = 0
        nb_1000 = 0
        nb_500 = 0
        cc_set_10p = set()
        cc_set_1000 = set()
        cc_set_500 = set()
        nb_20pd = 0
        nb_50pd = 0
        threshold_10p = int(self.total/10)
        if self.resolver_AS in big_as_list:
            main_count = big_as_list[self.resolver_AS]
        else:
            main_count = 0
        ratio_3rdp = self.total /(self.total + main_count)

        for cc_as in self.top_list:
            if cc_as.count > max_dep:
                max_dep = cc_as.count
            if cc_as.count > threshold_10p:
                sum_10p += cc_as.count
                nb_10p += 1
                if not (cc_as.query_cc) in cc_set_10p:
                    cc_set_10p.add(cc_as.query_cc)
            if cc_as.count > 1000:
                sum_1000 += cc_as.count
                nb_1000 += 1
                if not (cc_as.query_cc) in cc_set_1000:
                    cc_set_1000.add(cc_as.query_cc)
            if cc_as.count > 500:
                sum_500 += cc_as.count
                nb_500 += 1
                if not (cc_as.query_cc) in cc_set_500:
                    cc_set_500.add(cc_as.query_cc)
                    
            if cc_as.query_AS in big_as_list:
                as_count = big_as_list[cc_as.query_AS]
                if 5*cc_as.count > as_count:
                    nb_20pd += 1
                if 2*cc_as.count > as_count:
                    nb_50pd += 1
        t = [
            self.resolver_AS,
            float(sum_10p/self.total),
            float(sum_1000/self.total),
            float(sum_500/self.total),
            float(max_dep/self.total),
            nb_10p,
            nb_1000,
            nb_500,
            len(cc_set_10p),
            len(cc_set_1000),
            len(cc_set_500),
            nb_20pd,
            nb_50pd,
            float(ratio_3rdp),
            self.total ]
        return t;

    def extract_group(self, big_as_list, threshold, top_list):
        for cc_as in self.top_list:
            if cc_as.query_AS in big_as_list:
                if cc_as.count >= threshold*big_as_list[cc_as.query_AS] or \
                    ((not self.resolver_AS in big_as_list) and \
                    cc_as.count >= threshold*self.total):
                    top_list.add_group(self.resolver_AS, cc_as.query_AS)

    def trim_graph(self, big_as_list, threshold):
        total = 0
        new_list = []
        for cc_as in self.top_list:
            if cc_as.query_AS in big_as_list and \
                cc_as.count >= threshold*big_as_list[cc_as.query_AS]:
                new_list.append(cc_as)
                total += cc_as.count
            elif (not self.resolver_AS in big_as_list) and \
                cc_as.count >= threshold*self.total and \
                cc_as.query_AS in big_as_list:
                print(self.resolver_AS + " (" + self.AS_name + ": " + str(self.total) + "), " + cc_as.query_AS + " (" + cc_as.AS_name + ": " + str(cc_as.count)  + " / " + str(big_as_list[cc_as.query_AS]) + ")")
        self.top_list = new_list

class top_resolvers_list:
    def __init__(self):
        self.top_list = dict()
        self.sum_total = 0
        self.big_as_list = dict()
        self.groups = dict()

    def process_row(self, x):
        resolver_AS = x['resolver_AS']
        if x['query_AS'] == 'total':
            if not resolver_AS in self.top_list:
                self.top_list[resolver_AS] = top_resolver(resolver_AS, x['query_cc'], x['count'], x['AS_name'], x['has_name'])
            else:
                print("Duplicate resolver: " + resolver_AS)
                exit(-1)
        else:
            if not resolver_AS in self.top_list:
                print("Missing resolver total: " + resolver_AS)
                exit(-1)
            else:
                self.top_list[resolver_AS].add_query_as(x['query_AS'], x['query_cc'], x['count'], x['AS_name'], x['has_name'])

    def load_file(self, saved_file):
        df = pd.read_csv(saved_file)
        df.apply(lambda x: self.process_row(x), axis=1)

    def get_names(self, know_names):
        all_found = True
        for resolver_AS in self.top_list:
            all_found &= self.top_list[resolver_AS].get_names(know_names)

    def export_top(self, top_file):
        t = []
        for resolver_AS in self.top_list:
            t += self.top_list[resolver_AS].top_rows()
        df = pd.DataFrame(t, columns=resolver_cc_as.top_headers())
        df.to_csv(top_file)

    def process_big_as(self, x):
        if ('asn' in x) and ('count' in x): 
            resolver_AS = x['asn']
            count = x['count']
            self.big_as_list[resolver_AS] = count

    def import_top_as(self, top_as_file):
        df = pd.read_csv(top_as_file)
        df.apply(lambda x: self.process_big_as(x), axis=1)

    def export_features(self, feature_file):
        t = []
        for resolver_AS in self.top_list:
            t.append(self.top_list[resolver_AS].export_features(self.big_as_list))
        df = pd.DataFrame(t, columns=top_resolver.feature_headers())
        df.to_csv(feature_file, sep=',')
        print("Saved features in " + feature_file)

    def add_group(self, as1, as2):
        if as1 > as2:
            key = as1
            target = as2
        else:
            key = as2
            target = as1
        while key != target:
            if key in self.groups:
                as3 = self.groups[key]
                if as3 > target:
                    # we end we two records, key -> target and as3 -> target.
                    # we need a recursion, because as3 may already exist.
                    self.groups[key] = target
                    key = as3
                    continue
                else:
                    # we end we two records, key -> as3, which exist, and target->as3
                    key = target
                    target = as3
                    continue
            else:
                self.groups[key] = target
                break

    def trim_groups(self):
        # look for chains like group[x] = y, group[y] = z,
        # replace with group[x] = z, group[y] = z
        looping = True
        while looping:
            looping = False
            for key in self.groups:
                target = self.groups[key]
                if target in self.groups:
                    self.groups[key] = self.groups[target]
                    looping = True

    def extract_groups(self, threshold=0.75):
        for resolver_AS in self.top_list:
            self.top_list[resolver_AS].extract_group(self.big_as_list, threshold, self)
        self.trim_groups()

    def save_graph(self, top_file):
        t = []
        for key in self.groups:
            t.append([ key, self.groups[key]])
        df = pd.DataFrame(t, columns=["AS", "AS_group"])
        df.to_csv(top_file)
        print("Saved " + top_file)

# Main program
if __name__ == "__main__":
    time_start = time.time()
    source_path = Path(__file__).resolve()
    resolver_dir = source_path.parent
    auto_source_dir = resolver_dir.parent
    print("Auto source path is: " + str(auto_source_dir) + " (source: " + str(source_path) + ")")
    source_dir = os.path.join(auto_source_dir, "data") 
    ip2a4_file = os.path.join(source_dir, "ip2as.csv") 
    ip2a6_file = os.path.join(source_dir, "ip2asv6.csv")
    as_names_file = os.path.join(source_dir, "as_names.csv") 
    if sys.argv[1] != '+' and sys.argv[1] != '!' and sys.argv[1] != '=' and sys.argv[1] != '?':
        ip2a4 = ip2as.ip2as_table()
        ip2a4.load(ip2a4_file)
        ip2a6 = ip2as.ip2as_table()
        ip2a6.load(ip2a6_file)
    else:
        ip2a4 = None
        ip2a6 = None
    as_names = ip2as.asname()
    as_names.load(as_names_file)
    time_loaded = time.time()
    print("Tables loaded at " + str(time_loaded - time_start) + " seconds.")
    if sys.argv[1] == '+':
        # load files as df
        r_list = resolver_list()
        for file_name in sys.argv[3:]:
            r_list.load_file(file_name)
        print("Sum total: " + str(r_list.sum_total))
        r_df = r_list.export_df(as_names)
        r_df.to_csv(sys.argv[2], sep=",")
        print("Saved csv file at " + str(time.time() - time_start) + " seconds.")
        exit(0)
    if sys.argv[1] == '!':
        # load summary file as df
        r_list = resolver_list()
        r_list.load_file(sys.argv[3])
        print("Sum total: " + str(r_list.sum_total))
        if r_list.sum_total < 10000:
            threshold=100
        else:
            threshold=5000
        r_list.export_top(sys.argv[2], as_names, threshold=threshold)
        print("Exported top file at " + str(time.time() - time_start) + " seconds.")
        exit(0)
    if sys.argv[1] == '=':
        know_names = top_as.known_AS_names()
        if len(sys.argv) > 3:
            try:
                know_names.load_top_as(sys.argv[3])
            except Exception as exc:
                traceback.print_exc()
                print('\nCode generated an exception: %s' % (exc))
                print("Cannot get names from top AS list: " + sys.argv[3])
                exit(-1)
        top_list = top_resolvers_list()
        top_list.load_file(sys.argv[2])
        top_list.get_names(know_names)
        top_list.export_top(sys.argv[2])
        print("Updated top file at " + str(time.time() - time_start) + " seconds.")
        exit(0)
    if sys.argv[1] == '?':
        top_list = top_resolvers_list()
        top_list.load_file(sys.argv[2])
        top_list.import_top_as(sys.argv[3])
        top_list.export_features(sys.argv[4])
        top_list.extract_groups()
        print("Found " + str(len(top_list.groups)) + " resolvers in groups.")
        top_list.save_graph(sys.argv[5])
        exit(0)

    as_names = ip2as.asname()
    as_names.load(as_names_file)
    print("AS names loaded at " + str(time.time() - time_start) + " seconds.")

    r_list =  resolver_list()
    nb_events = r_list.load(sys.argv[1], ip2a4, ip2a6, as_names,
        experiment=['0du'], rr_types = [ 'A', 'AAAA', 'HTTPS' ], time_start = time_start)
    print("Loaded " + str(nb_events) + " events for " + str(len(r_list.resolvers)) + " resolvers at " + str(time.time() - time_start) + " seconds.")

    r_df = r_list.export_df(as_names)
    r_df.to_csv(sys.argv[2], sep=",")
    print("Saved csv file at " + str(time.time() - time_start) + " seconds.")





