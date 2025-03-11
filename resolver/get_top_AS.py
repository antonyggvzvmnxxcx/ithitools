# Get the list AS per country in the input file

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
import country
import time
import rdap_names

class cc_as:
    def __init__(self, query_AS, query_cc, uid):
        self.query_AS = query_AS
        self.query_cc = query_cc
        self.uid_set = set()
        self.uid_set.add(uid)

    def add_uid(self, uid):
        self.uid_set.add(uid)

    def as_row(self, as_names):
        topas_name = ""
        if self.query_AS in top_as.TopAS:
            topas_vec = top_as.TopAS[self.query_AS]
            topas_name = topas_vec[0]
        return [ \
            self.query_cc, \
            self.query_AS, \
            as_names.name(self.query_AS) , \
            topas_name,
            len(self.uid_set) ]

    def headers():
        return [ 
            'query_cc', \
            'query_AS', \
            'AS_name', \
            'Top_AS_Name', \
            'count', \
           ]


class cc_as_list:
    def __init__(self):
        self.cc_AS = dict()


    def load(self, file_name, rr_types=[], experiment=[], log_threshold = 15625, time_start = 0):
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
                    key = x.query_cc + x.query_AS
                    if key in self.cc_AS:
                        self.cc_AS[key].add_uid(x.query_user_id)
                    else:
                        self.cc_AS[key] = cc_as(x.query_AS, x.query_cc, x.query_user_id);
                    nb_events += 1
                    if (nb_events%lth) == 0:
                        print("loaded " + str(nb_events) + " events at " + str(time.time() - time_start))
                        lth *= 2
        return nb_events

    def export_df(self, as_names):
        r = []
        for key in self.cc_AS:
            r.append(self.cc_AS[key].as_row(as_names))
        r.sort(key=lambda x: x[4], reverse=True)
        df = pd.DataFrame(r, columns=cc_as.headers())
        return df


class cc_as_summary:
    def __init__(self):
        self.cc_AS = dict()
        self.candidates = []

    def load_sum(self, x):
        key =  str(x["query_cc"]) + str(x["query_AS"])
        if key in self.cc_AS:
            self.cc_AS[key][4] += x["count"]
        else:
            self.cc_AS[key] = [ x.query_cc, x.query_AS, x.AS_name, x.Top_AS_Name, x["count"] ]

    def load(self, file_name):
        df = pd.read_csv(file_name)
        df.apply(lambda x: self.load_sum(x), axis=1)

    def export_df(self):
        r = list(self.cc_AS.values())
        r.sort(key=lambda x: x[4], reverse=True)
        df = pd.DataFrame(r, columns=cc_as.headers())
        return df

    def process_candidate(self, x):
        print(str(x))
        key =  str(x['CC']) + str(x['ASN'])
        count = 0
        if key in self.cc_AS:
            cc_as = self.cc_AS[key]
            count = cc_as[4]
        row = [ x['CC'], x['ASN'], x['Name'], x['Type'], count ]
        self.candidates.append(row)

    def load_candidates(self, candidate_input_file):
        df = pd.read_csv(candidate_input_file)
        df.apply(lambda x: self.process_candidate(x), axis=1)

    def save_candidates(self, candidate_output_file):
        headers = [ 'CC', 'ASN', 'Name', 'Type', 'count' ]
        cdf = pd.DataFrame(self.candidates, columns=headers)
        cdf.to_csv(candidate_output_file)


class cc_top:
    def __init__(self, cc):
        self.cc = cc
        self.region = ''
        self.top_n = []

    def prune(self):
        limit = 5
        if self.cc == 'US' or self.cc == 'IN' or self.cc == 'CN':
            limit = 10
        self.top_n.sort(key=lambda x: x[4], reverse=True)
        self.top_n = self.top_n[:limit]

class cc_tops:
    def __init__(self):
        self.cc_lists = dict()
        self.cc_as_type = dict()

    def load_top(self, summary,  threshold):
        for maybe_top in summary.cc_AS:
            mb = summary.cc_AS[maybe_top]
            if mb[4] > threshold and isinstance(mb[0], str):
                if not mb[0] in self.cc_lists:
                    self.cc_lists[mb[0]] = cc_top(mb[0])
                self.cc_lists[mb[0]].top_n.append(mb)
        for cc in self.cc_lists:
            self.cc_lists[cc].prune()

    def load_cc_as_type(self, x):
        v = x['Type']
        if  isinstance(v, str) and len(str(v)) > 0:
            key = x['CC'] + x['ASN']
            self.cc_as_type[key] = v

    def load_old_summary(self, file_name):
        df = pd.read_csv(file_name)
        df.apply(lambda x: self.load_cc_as_type(x), axis=1)

    def export(self, file_name):
        r = []
        for cc in self.cc_lists:
            region = country.cc_to_region[cc]
            for as_data in self.cc_lists[cc].top_n:
                asn = as_data[1]
                key = cc + asn
                as_type = "mix"
                if key in self.cc_as_type:
                    as_type = self.cc_as_type[key]
                x = [  region, cc, asn, as_data[2], as_type, as_data[4], False ]

                r.append(x)
        df = pd.DataFrame(r, columns=['region', 'CC', 'asn', 'as_name', 'as_type', 'count', 'has_name' ])
        df.to_csv(file_name)

class cc_tops_names:
    def __init__(self):
        self.next_rev = []
        self.is_failing = False
        self.successes = 0
        self.missing = 0

    def load_one_name(self, x):
        region = x['region']
        cc = x['CC']
        asn = x['asn']
        as_name = x['as_name']
        as_type = x['as_type']
        count = x['count']
        has_name = x['has_name']
        success = False

        if not has_name and not self.is_failing:
            success, x_name = rdap_names.get_as_name_by_region(region, asn, as_name)
            if not success:
                self.is_failing = True
                print("Failed call after " + str(self.successes) + " successes.")
            else:
                as_name = x_name
                has_name = True
                self.successes += 1

        if not has_name: 
            self.missing += 1
        r = [ region, cc, asn, as_name, as_type, count, has_name ]
        self.next_rev.append(r)

    def load_names(self, file_name):
        df = pd.read_csv(file_name)
        df.apply(lambda x: self.load_one_name(x), axis=1)
        print("Still missing: " + str(self.missing))
        ndf = pd.DataFrame(self.next_rev, columns=['region', 'CC', 'asn', 'as_name', 'as_type', 'count', 'has_name' ])
        ndf.to_csv(file_name)

# Main program
if __name__ == "__main__":
    if sys.argv[1] == '+':
        cc_as_sum = cc_as_summary()
        for csv in sys.argv[3:]:
            print("loading " + csv)
            cc_as_sum.load(csv)
        df = cc_as_sum.export_df()
        print("Loaded " + str(df.shape[0]) + " rows")
        df.to_csv(sys.argv[2], sep=",")
        print("wrote " + sys.argv[2])
        exit(0)
    if sys.argv[1] == '?':
        cc_as_sum = cc_as_summary()
        cc_as_sum.load(sys.argv[2])
        print("Loaded " + str(len(cc_as_sum.cc_AS)) + " cc_AS")
        cc_as_sum.load_candidates(sys.argv[3])
        print("Loaded " + str(len(cc_as_sum.candidates)) + " top candidates")
        cc_as_sum.save_candidates(sys.argv[3])
        print("wrote " + sys.argv[3])
        exit(0)
    if sys.argv[1] == '!':
        cc_as_sum = cc_as_summary()
        cc_as_sum.load(sys.argv[2])
        print("Loaded " + str(len(cc_as_sum.cc_AS)) + " cc_AS")
        tops = cc_tops()
        tops.load_top(cc_as_sum, 10000)
        tops.load_old_summary(sys.argv[3])
        print("Found top 5 or 10 for " + str(len(tops.cc_lists)) + " countries.")
        tops.export(sys.argv[4])
        print("wrote " + sys.argv[4])
        exit(0)
    if sys.argv[1] == '=':
        tn = cc_tops_names()
        tn.load_names(sys.argv[2])
        exit(0)


    time_start = time.time()
    source_path = Path(__file__).resolve()
    resolver_dir = source_path.parent
    auto_source_dir = resolver_dir.parent
    source_dir = os.path.join(auto_source_dir, "data") 
    as_names_file = os.path.join(source_dir, "as_names.csv")

    as_names = ip2as.asname()
    as_names.load(as_names_file)
    print("AS names loaded at " + str(time.time() - time_start) + " seconds.")


    as_list = cc_as_list()
    nb_events = as_list.load(sys.argv[1], experiment=['0du'], \
        rr_types = [ 'A', 'AAAA', 'HTTPS' ], time_start = time_start)
    print(str(nb_events) + " for " + str(len(as_list.cc_AS)) + " cc.AS loaded at " + str(time.time() - time_start) + " seconds.")

    as_df = as_list.export_df(as_names)
    as_df.to_csv(sys.argv[2], sep=",")
    print("Saved csv file at " + str(time.time() - time_start) + " seconds.")





