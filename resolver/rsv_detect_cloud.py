# Detecting cloud providers.
# 
# We know that some queries are not (or not only) served by resolvers in the
# "same AS". Among those, some of the resolvers are "cloud providers". We
# identify tham by a set of characteristics:
#
# 1. They serve more than 1000 queries across all domains
# 2. They do not serve more than 40% of the queries of their larger "query AS"
# 3. They operate in at least 2 different countries.
# 
# The selection operates by first computing a table of top resolvers. This
# is a pivot of the statistics "per query AS" that lists the resolvers for
# each Query AS. We will list the resolver AS, and for each resolver
# AS we list the query ASes and their country. 
#
# We then apply the selection criteria listed above to recognize the 
# "cloud AS", first by discarding all resolvers that serve fewer than
# 1000 queries, and then by selecting based on the criteria. We
# produce a graph showing the results of the selection.

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
import csv

class cc_as_total:
    def __init__(self, query_cc, query_AS, AS_name="", has_name=False):
        self.query_cc = query_cc
        self.query_AS = query_AS
        self.AS_name = AS_name
        self.has_name = has_name
        self.count = 0

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
        self.r_AS = dict()
        self.total = 0
        self.nb_cc = 0
        self.nb_cc_500 = 0
        self.bigger = 0
        self.bigger_AS = "AS0"
        self.bigger_cc = "ZZ"
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
        self.r_AS = dict()
        for key in self.r_cc_AS:
            cc_as = self.r_cc_AS[key]
            self.total += cc_as.count
            if cc_as.query_AS in self.r_AS:
                self.r_AS[cc_as.query_AS] += cc_as.count
            else:
                self.r_AS[cc_as.query_AS] = cc_as.count

    def do_cloud_checks(self):
        cc_set = set()
        cc_500_set = set()
        bigger = 0
        bigger_AS = "AS0"
        bigger_cc = "ZZ"
        for key in self.r_cc_AS:
            cc_as = self.r_cc_AS[key]
            qcc = cc_as.query_cc
            if qcc == 'HK' or qcc == 'MO':
                qcc = 'CN'
            if not qcc in cc_set:
                cc_set.add(qcc)
            if cc_as.count >= 500 and not cc_as.query_cc in cc_500_set:
                cc_500_set.add(cc_as.query_cc)
            if cc_as.count > bigger:
                bigger = cc_as.count
                bigger_AS = cc_as.query_AS
                bigger_cc = cc_as.query_cc
        self.nb_cc = len(cc_set)
        self.nb_cc_500 = len(cc_500_set)
        self.bigger = bigger
        self.bigger_AS = bigger_AS
        self.bigger_cc = bigger_cc

    def extract_groups(self, rsv_list, threshold_factor):
        for query_AS in self.r_AS:
            count = self.r_AS[query_AS]
            if query_AS in rsv_list.top_AS_list and \
               (count >= threshold_factor*rsv_list.top_AS_list[query_AS] or \
                count >= threshold_factor*self.total):
               rsv_list.add_group(self.resolver_AS, query_AS)

class resolver_list:
    def __init__(self):
        self.resolvers = dict()
        self.top_AS_list = dict()
        self.sum_total = 0
        self.groups = dict()
        self.naming = top_as.known_AS_names()

    def get_name(self, asn, as_names):
        if asn in self.naming.as_names:
            return self.naming.as_names[asn]
        else:
            return as_names.name(asn)


    def load_csv_log(self, csv_file):
        nb_events = 0
        open_rsv_set = set (['googlepdns', 'cloudflare', 'opendns', 'quad9', 'level3', 'neustar', 'he' ])
        with open(csv_file, newline='') as csvfile:
            rsv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            is_first = True
            is_second = True
            header_row = ['resolver_AS', 'query_cc', 'query_AS', 'resolver_tag' ]
            header_index = [-1, -1, -1, -1]

            for row in rsv_reader:
                if is_first:
                    # print(",".join(row))
                    for i in range(0, len(header_row)):
                        for x in range(0, len(row)):
                            if row[x] == header_row[i]:
                            #   print("row[" + str(x) + "](" + str(row[x]) + ") == " + header_row[i])
                                header_index[i] = x
                                break
                            #else:
                            #    print(row[x] + " != " + header_row[i])
                        if header_index[i] < 0:
                            print("Could not find " + header_row[i] + " in " + ','.join(row))
                            exit(-1)
                    is_first = False
                else:
                    if (is_second):
                        resolver_AS = row[header_index[0]]
                        query_cc = row[header_index[1]]
                        query_AS = row[header_index[2]]
                        resolver_tag = row[header_index[3]]
                        
                        if not isinstance(query_cc, str) or len(query_cc) > 2:
                            query_cc = 'ZZ'

                        if resolver_AS != 'AS0' and (not resolver_AS == query_AS) and (not resolver_tag in open_rsv_set):
                            if not resolver_AS in self.resolvers:
                                self.resolvers[resolver_AS] = resolver(resolver_AS)
                            self.resolvers[resolver_AS].load_row(query_cc, query_AS, 1)

                            self.sum_total += 1
                    nb_events += 1
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

    def process_summary_row(self, x, top_AS_list):
        query_AS = x['q_AS']
        uids = x['uids']
        if query_AS in top_AS_list:
            top_AS_list[query_AS] += uids
        else:
            top_AS_list[query_AS] = uids

    def compute_top_list(self, summary_file_name, threshold):
        # Create a list of top resolvers from summary file
        # Process in two pass: first, compute a per AS total for all cc/AS in the summary,
        # then keep only those with more than threshold uuids in the top AS list.
        top_AS_list = dict()
        df = pd.read_csv(summary_file_name)
        df.apply(lambda x: self.process_summary_row(x, top_AS_list), axis=1)

        self.top_AS_list = dict()
        for query_AS in top_AS_list:
            if top_AS_list[query_AS] >= threshold:
                self.top_AS_list[query_AS] = top_AS_list[query_AS]
        print("Computed top AS list, len: " + str(len(self.top_AS_list)))

        # Compute the list of AS per resolver, to prepare for group computation.
        for resolver_AS in  self.resolvers:
            rsv = self.resolvers[resolver_AS];
            rsv.compute_top()

    def export_cloud_candidates(self, known_cloud, as_names):
        t = []
        for resolver_AS in self.resolvers:
            rsv = self.resolvers[resolver_AS];
            rsv.do_cloud_checks()
            is_cloud = (resolver_AS in known_cloud)
            is_lower_40 = (0.4*rsv.total > rsv.bigger)
            r = [rsv.resolver_AS, rsv.total, rsv.nb_cc, rsv.nb_cc_500, rsv.bigger_cc, rsv.bigger_AS, rsv.bigger, is_cloud, is_lower_40, 
                 self.get_name(rsv.resolver_AS, as_names) ]
            t.append(r)
        df = pd.DataFrame(t, columns=['resolver_AS', 'total', 'nb_cc', 'nb_cc_500', 'bigger_cc', 'bigger_AS', 'bigger_count', 'is_cloud', 'is_lower_40', 'name' ])
        return df

    def compare_groups(self, as1, as2):
        ret = True
        n_as1 = 0
        n_as2 = 0
        if as1 in self.top_AS_list:
            n_as1 = self.top_AS_list[as1]
        if as2 in self.top_AS_list:
            n_as2 = self.top_AS_list[as2]
        if n_as2 < n_as1:
            ret = False
        elif n_as2 == n_as1 and as2 > as1:
            ret = False
        return ret

    def add_group(self, as1, as2):
        if self.compare_groups(as1, as2):
            key = as1
            target = as2
        else:
            key = as2
            target = as1
        while key != target:
            if key in self.groups:
                as3 = self.groups[key]
                if self.compare_groups(as3, target):
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

    def extract_groups(self, threshold_factor):
        for resolver_AS in self.resolvers:
            rsv = self.resolvers[resolver_AS];
            rsv.extract_groups(self, threshold_factor)

    def export_groups(self, group_file, as_names):
        t = []
        for key in self.groups:
            if key in self.top_AS_list:
                t.append([ key, self.get_name(key, as_names), self.groups[key],self.get_name(self.groups[key], as_names) ] )
        df = pd.DataFrame(t, columns=["AS", "AS_name", "AS_group", "AS_group_name" ])
        df.to_csv(group_file)
        print("Saved " + group_file)

# Main program
if __name__ == "__main__":
    time_start = time.time()
    if len(sys.argv) < 3:
        usage()
        exit(-1)

    output_dir = sys.argv[1]
    csv_files = sys.argv[2:]

    print("Output: " + output_dir)
    print("Input: " + str(csv_files))


    time_start = time.time()
    source_path = Path(__file__).resolve()
    resolver_dir = source_path.parent
    auto_source_dir = resolver_dir.parent
    print("Auto source path is: " + str(auto_source_dir) + " (source: " + str(source_path) + ")")
    source_dir = os.path.join(auto_source_dir, "data") 
    ip2a4_file = os.path.join(source_dir, "ip2as.csv") 
    ip2a6_file = os.path.join(source_dir, "ip2asv6.csv")
    ip2a4 = None
    ip2a6 = None
    as_names_file = os.path.join(source_dir, "as_names.csv") 

    #ip2a4 = ip2as.ip2as_table()
    #ip2a4.load(ip2a4_file)
    #ip2a6 = ip2as.ip2as_table()
    #.load(ip2a6_file)
    as_names = ip2as.asname()
    as_names.load(as_names_file)
    time_loaded = time.time()

    print("Tables loaded at " + str(time_loaded - time_start) + " seconds.")

    as_names = ip2as.asname()
    as_names.load(as_names_file)
    print("AS names loaded at " + str(time.time() - time_start) + " seconds.")

    r_list =  resolver_list()
    old_res_nb = 0
    for csv_file in csv_files:
        nb_events = r_list.load_csv_log(csv_file)
        print("Loaded " + str(nb_events) + " events, " + str(len(r_list.resolvers) - old_res_nb) + " new resolvers at " + str(time.time() - time_start) + " seconds.")
        old_res_nb = len(r_list.resolvers)
    
    print("Sum total: " + str(r_list.sum_total))
    if r_list.sum_total < 100000:
        threshold=100
    else:
        threshold=5000
    print("Threshold: " + str(threshold))

    summary_file_name = os.path.join(output_dir, "summary.csv" )
    r_list.compute_top_list(summary_file_name, threshold)

    known_cloud = set([
        "AS396982", #"GOOGLE-CLOUD-PLATFORM",
        "AS20940", #"AKAMAI-ASN1",
        "AS16509" #"AMAZON-02"
        ])
    df = r_list.export_cloud_candidates(known_cloud, as_names)
    cloud_candidate_file = os.path.join(output_dir, "cloud_candidate.csv" )
    df.to_csv(cloud_candidate_file, sep=',')
    

    groups_file = os.path.join(output_dir, "groups.csv" )
    r_list.extract_groups(0.9)
    r_list.trim_groups()
    r_list.export_groups(groups_file, as_names)
    print("Found " + str(len(r_list.groups)) + " resolvers in groups.")

