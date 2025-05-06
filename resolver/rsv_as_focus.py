# Study of duplicate queries.
#
# We consider duplicate queries as queries with the same "query AS" and the
# same "query ID", but appearing with different "resolver AS".
#
# We already list the number of duplicates as part of the "sumamry".
# We first produce a graph of all ISP "duplicates". Then we
# find a list of Query AS with more than 10k impressions and 5% or
# more duplicates. We perform a second pass in which we get the
# details of transactions done by these ISPs.
#
# For each transaction, we have multiple possible resolver AS, or
# even resolver IP, and multiple record types. We operate a first
# tabulation by query_AS, uique ID, resolver_AS, resolver IP, 
# record type, and time. We should keep all that for the detailed analysis.
#
# Study by record type:
# Can we prepare a summary that include a line per record type?
# This will help us detect whether the spread is the same for all RR types.
#
# Study of repetitions:
# Can we prepare a summary in which the data is not filtered, i.e.,
# count one for each query?
# 
# The list of tags is defined in rsv_log_parse as:
# tag_list = [ 'Same_AS', 'Same_group',  'Cloud', 'Same_CC', 'Other_cc', 'googlepdns', 'cloudflare', \
#           'opendns', 'quad9', 'level3', 'neustar', 'he' ]
# for the purpose of detecting duplicates, we treat 'Same_AS'and 'Same_group' as a single category,
# 'isp'. We will ony retain events that are present in at least two of the selected categories.
# 

import sys
import os
from pathlib import Path
import ip2as
import rsv_log_parse
#import rsv_both_graphs
import pandas as pd
import traceback
import top_as
import time
import csv
import random
import ipaddress

def extract_AS_from_summary(summary_file, threshold=10000):
    as_dups = []
    as_reps = []
    with open(summary_file, newline='') as csvfile:
        rsv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        is_first = True
        is_second = True
        header_row = [ 'q_AS', 'uids','q_uid_tags', 'q_repeats', 'q_cc' ]
        header_index = [ -1, -1, -1, -1, -1 ]

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
                    #print(",".join(row))
                    #for i in range(0, len(header_row)):
                    #    print(str(i) + ": x[" + header_row[i] + "] = " + str(row[header_index[i]]))
                    is_second = False
                query_cc = row[header_index[4]]
                query_AS = row[header_index[0]]
                uids = int(row[header_index[1]])
                q_uid_tags = int(row[header_index[2]])
                q_repeats = int(row[header_index[3]])
                if uids >= threshold:
                    dups = q_uid_tags / uids
                    if dups >= 1.05:
                        as_dups.append(query_cc + query_AS)
                    reps = q_repeats / uids
                    if reps > 5:
                        as_reps.append(query_cc + query_AS)
    return as_dups, as_reps

class detail_query:
    def __init__(self, query_time, resolver_IP, resolver_AS):
        self.query_time = query_time
        self.resolver_IP = resolver_IP
        self.resolver_AS = resolver_AS

class detail_uid:
    def __init__(self, uid):
        self.queries = []
        self.uid = uid
        
    def add_query(self, query_time, resolver_IP, resolver_AS):
        self.queries.append(detail_query(query_time, resolver_IP, resolver_AS))

class detail_resolver_tag:
    def __init__(self, resolver_tag):
        self.q_uids = dict()
        self.resolver_tag = resolver_tag

    def add_query(self, uid, query_time, resolver_IP, resolver_AS):
        if not uid in self.q_uids:
            self.q_uids[uid] = detail_uid(uid)
        self.q_uids[uid].add_query(query_time, resolver_IP, resolver_AS)

class detail_rr_type:
    def __init__(self, rr_type):
        self.q_tags = dict()
        self.rr_type = rr_type
        #self.tag_check = set(rsv_log_parse.tag_list)

    def add_query(self, resolver_tag, uid, query_time, resolver_IP, resolver_AS):
        #print("    Add query to " + self.rr_type)
        #if not resolver_tag in self.tag_check:
        #    print("Unexpected tag: " + resolver_tag + " in: " + self.rr_type)
        #    exit(-1)
        if not resolver_tag in self.q_tags:
            self.q_tags[resolver_tag] = detail_resolver_tag(resolver_tag)
        self.q_tags[resolver_tag].add_query(uid, query_time, resolver_IP, resolver_AS)

def parse_cc_as_net_key(key):
    q_cc = key[0:2]
    as_plus_net = key[2:].split("_")
    q_AS = as_plus_net[0]
    if len(as_plus_net) > 1:
        q_net = as_plus_net[1]
    else:
        q_net = ""
    return q_cc, q_AS, q_net

class detail_cc_as_net:
    def __init__(self, key):
        self.rr_types = dict()
        self.uids = dict()
        self.query_cc, self.query_AS, self.query_net = parse_cc_as_net_key(key)

    def add_query(self, rr_type, resolver_tag, uid, query_time, resolver_IP, resolver_AS):
        #print("Add query to " + self.query_cc + "/" + self.query_AS)
        if not rr_type in self.rr_types:
            self.rr_types[rr_type] = detail_rr_type(rr_type)
        self.rr_types[rr_type].add_query(resolver_tag, uid, query_time, resolver_IP, resolver_AS)
        if not uid in self.uids:
            self.uids[uid] = set()
        class_tag = resolver_tag
        if class_tag == 'same_AS' or class_tag == 'same_group':
            class_tag = 'isp'
        if not class_tag in self.uids[uid]:
            self.uids[uid].add(class_tag)

class detailed_log:
    def __init__(self, as_list):
        self.as_set = set(as_list)
        self.cc_ases = dict()
        self.tag_check = set(rsv_log_parse.tag_list)
        #self.rr_check = set(['A', 'AAAA', 'HTTPS'])
        self.as0_IP = dict()

    def add_query(self, key, rr_type, resolver_tag, uid, query_time, resolver_IP, resolver_AS):
        #if not rr_type in self.rr_check:
        #    print("Unexpected rr: " + rr_type + " in:\n" + ",".join(row))
        #    exit(-1)
        #if not resolver_tag in self.tag_check:
        #    print("Unexpected tag: " + resolver_tag + " in:\n" + ",".join(row))
        #    exit(-1)
        if key in self.cc_ases:
           self.cc_ases[key].add_query(rr_type, resolver_tag, uid, query_time, resolver_IP, resolver_AS)

    def load_csv_log(self, saved_file):
        #df = pd.read_csv(saved_file)
        #df.apply(lambda x: self.load_df_row(x), axis=1)
        #return df.shape[0]

        nb_events = 0
        with open(saved_file, newline='') as csvfile:
            rsv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            is_first = True
            is_second = True
            header_row = [ 'query_time', 'resolver_tag', 'query_cc', 'query_AS', 'query_user_id', 'resolver_IP', 'resolver_AS', 'rr_type', 'query_IP' ]
            header_index = [ -1, -1, -1, -1, -1,  -1,  -1, -1, -1 ]

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
                        #print(",".join(row))
                        #for i in range(0, len(header_row)):
                        #    print(str(i) + ": x[" + header_row[i] + "] = " + str(row[header_index[i]]))
                        is_second = False
                    query_time = float(row[header_index[0]])
                    resolver_tag = row[header_index[1]]
                    #if not resolver_tag in self.tag_check:
                    #    print("Unexpected tag: " + resolver_tag + " in:\n" + ",".join(row))
                    #    exit(-1)
                    query_cc = row[header_index[2]]
                    query_AS = row[header_index[3]]
                    key = query_cc + query_AS
                    uid = row[header_index[4]]
                    resolver_IP = row[header_index[5]]
                    resolver_AS = row[header_index[6]]
                    rr_type = row[header_index[7]]
                    query_IP = row[header_index[8]]
                    net_string = str( ipaddress.ip_network(query_IP + "/24", strict=False))
                    key_plus_net = key + "_" + net_string
                    if query_AS in self.as_set:
                        if not key in self.cc_ases:
                            self.cc_ases[key] = detail_cc_as_net(key)
                        if not key_plus_net in self.cc_ases:
                            self.cc_ases[key_plus_net] = detail_cc_as_net(key_plus_net)
                        self.add_query(key, rr_type, resolver_tag, uid, query_time, resolver_IP, resolver_AS)
                        self.add_query(key_plus_net, rr_type, resolver_tag, uid, query_time, resolver_IP, resolver_AS)
                        nb_events += 1
                        # track AS0 for potential issues
                        if resolver_AS == 'AS0':
                            if not resolver_IP in self.as0_IP:
                                self.as0_IP[resolver_IP] = 1
                            else:
                                self.as0_IP[resolver_IP] += 1
        return nb_events

    # create an AS0 report
    def as0_report(self):
        t = []
        for resolver_IP in self.as0_IP:
            r = [ resolver_IP, self.as0_IP[resolver_IP] ]
            t.append(r)
        t.sort(key=lambda x: x[1], reverse=True)
        df = pd.DataFrame(t, columns=['as0_IP', 'count' ])
        return df

    # create a report of duplicates, with 1 line per As per rrtype, and a summary line.
    def detailed_report(self, ASn):
        headers = [ 'query_cc', 'query_AS', 'query_net', 'rr_type', 'nb_uids', 'nb_dups' ]
        report_list = []
        for tag in rsv_log_parse.tag_list:
            headers.append(tag)
        keys = []
        for key in self.cc_ases.keys():
            query_cc, query_AS, query_net = parse_cc_as_net_key(key)
            if query_AS == ASn:
                # get the total record first
                keys.append(key)
        keys.sort()
        # Each key specifies a subnet for this CC/AS, or blank for the complete summary per CC/AS
        for key in keys:
            query_cc, query_AS, query_net = parse_cc_as_net_key(key)
            # key_uids is a set of all the keys found for this key, across all tags.
            key_uids = set()
            # key_report_tags contain an entry per tag, with a set of UID found for that tag.
            key_report_tags = dict()
            # key_report_tags contain the UID that wer found twice. This happens
            # if the UID is present in different key_tags
            key_dup_uids = set()
            # we accumulate first a set of reports for this key. It will only
            # be appended to the list if there are enough entries.
            key_reports = []
            for rr_type in self.cc_ases[key].rr_types:
                # set of all the uids seen for this RR
                rr_uids = set()
                # set of the UIDs seen in more than one tag for this RR
                rr_dups_uids = set()
                # We count the UIDs seen for each tag for this RR
                rr_report_tags = dict()
                for resolver_tag in self.cc_ases[key].rr_types[rr_type].q_tags:
                    if not resolver_tag in rr_report_tags:
                        rr_report_tags[resolver_tag] = set()
                    for uid in self.cc_ases[key].rr_types[rr_type].q_tags[resolver_tag].q_uids:
                        if not uid in rr_report_tags[resolver_tag]:
                            rr_report_tags[resolver_tag].add(uid)
                        # check whether this UID should be added at the key level
                        if not resolver_tag in key_report_tags:
                            key_report_tags[resolver_tag] = set()
                        if not uid in rr_uids:
                            rr_uids.add(uid)
                        elif not uid in rr_dups_uids:
                            rr_dups_uids.add(uid)
                        if not uid in key_report_tags[resolver_tag]:
                            # first time that we add the UID to the per tag list of the key for any record
                            key_report_tags[resolver_tag].add(uid)
                            if not uid in key_uids:
                                key_uids.add(uid)
                            elif not uid in key_dup_uids:
                                key_dup_uids.add(uid)

                # prepare the per AS+rr_type report
                report = [ query_cc, query_AS, query_net, rr_type, len(rr_uids), len(rr_dups_uids) ]
                for resolver_tag in rsv_log_parse.tag_list:
                    tag_uid_count = 0
                    if resolver_tag in rr_report_tags:
                        tag_uid_count = len(rr_report_tags[resolver_tag])
                    report.append(tag_uid_count)
                key_reports.append(report)
            # produce the per_key report
            if len(key_uids) > 20:
                for key_report in key_reports:
                    report_list.append(key_report)
                report = [ query_cc, query_AS, query_net, 'total', len(key_uids), len(key_dup_uids) ]
                for resolver_tag in rsv_log_parse.tag_list:
                    tag_uid_count = 0
                    if resolver_tag in key_report_tags:
                        tag_uid_count = len(key_report_tags[resolver_tag])
                    report.append(tag_uid_count)
                report_list.append(report)
        df = pd.DataFrame(report_list,columns=headers)
        return df

    # Summary for a given set of RR types and a single key:
    # We want to count the number of UID seen by the key for each "tag".
    # we also want to count the total number of UID and dups seen by the subnet
    # for the rr type, and update the number of UID and dups for the subnet
    # across all rr_types
    #
    def get_key_rr_summary(self, key, rr_types, key_uids, key_dups, key_report_tags):
        rr_uids = set()
        rr_dups = set()
        rr_report_tags = dict()
        rr_set = set(rr_types)
        for rr_type in self.cc_ases[key].rr_types:
            if not rr_type in rr_set:
                continue
            for resolver_tag in self.cc_ases[key].rr_types[rr_type].q_tags:
                # We count the UIDs seen for each tag for this RR
                if not resolver_tag in rr_report_tags:
                    rr_report_tags[resolver_tag] = set()
                    # we also maintain the count at the key level
                    if not resolver_tag in key_report_tags:
                        key_report_tags[resolver_tag] = set()
                for uid in self.cc_ases[key].rr_types[rr_type].q_tags[resolver_tag].q_uids:
                    if not uid in rr_report_tags[resolver_tag]:
                        rr_report_tags[resolver_tag].add(uid)
                        if not uid in rr_uids:
                            rr_uids.add(uid)
                        else:
                            rr_dups.add(uid)
                    # check whether this UID should be added at the key level
                    if not uid in key_report_tags[resolver_tag]:
                        # first time that we add the UID to the per tag list of the key for any record
                        key_report_tags[resolver_tag].add(uid)
                        if not uid in key_uids:
                            key_uids.add(uid)
                        elif not uid in key_dups:
                            key_dups.add(uid)
        # compute the per rr set report:
        rr_row = [ len(rr_uids), len(rr_dups) ]
        for resolver_tag in rsv_log_parse.tag_list:
            hits = 0
            if resolver_tag in rr_report_tags:
                hits = len(rr_report_tags[resolver_tag])
            rr_row.append(hits)

        return rr_row
    # create a flat report, with one line per large enough subnet

    def create_flat_report(self):
        # prepare the headers
        headers = [ 'query_cc', 'query_AS', 'query_net', 'nb_uids', 'nb_dups' ]
        headers2 = [ 'nb_uids', 'nb_dups' ]
        for r_t in [ 'A_', 'H_']:
            for h in headers2:
                headers.append(r_t + h)
            for resolver_tag in rsv_log_parse.tag_list:
                headers.append(r_t + resolver_tag)
        # prepare the keys
        keys = []
        for key in self.cc_ases.keys():
            query_cc, query_AS, query_net = parse_cc_as_net_key(key)
            if query_net != "":
                # get the total record first
                keys.append(key)
        keys.sort()
        # prepare the report
        subnet_list = []
        for key in keys:
            query_cc, query_AS, query_net = parse_cc_as_net_key(key)
            # initialize the global counts
            key_uids = set()
            key_dups = set()
            key_report_tags = dict()
            # get the summary for each of [ 'A', 'AAAA'] and ['HTTP']
            a_row = self.get_key_rr_summary(key, [ 'A', 'AAAA' ], key_uids, key_dups, key_report_tags)
            h_row = self.get_key_rr_summary(key, [ 'HTTPS' ], key_uids, key_dups, key_report_tags)
            # fill up the row
            key_row = [ query_cc, query_AS, query_net, len(key_uids), len(key_dups) ]
            for w in a_row:
                key_row.append(w)
            for w in h_row:
                key_row.append(w)
            subnet_list.append(key_row)
        flat_df = pd.DataFrame(subnet_list, columns=headers)
        return flat_df

    # extract a global list of UIDS
    def extract_queries(self, key, uid):
        queries = []
        # find the list of tags
        uid_tags = self.cc_ases[key].uids[uid]
        # iterate on the rr_types
        for rr_type in ['A', 'AAAA', 'HTTPS' ]:
            if rr_type in self.cc_ases[key].rr_types:
                for resolver_tag in uid_tags:
                    if resolver_tag in self.cc_ases[key].rr_types[rr_type].q_tags:
                        if uid in self.cc_ases[key].rr_types[rr_type].q_tags[resolver_tag].q_uids:
                            query_list = self.cc_ases[key].rr_types[rr_type].q_tags[resolver_tag].q_uids[uid].queries
                            for d_query in query_list:
                                record = [ key[:2], key[2:], uid, d_query.query_time, 0, rr_type, resolver_tag, d_query.resolver_AS, d_query.resolver_IP ]
                                queries.append(record)
        queries.sort(key=lambda x: x[3])
        return queries

def usage():
    print("Usage: python rsv_as_focus.py  <output_dir> *<ASnnn>  <csv_file> ... <csv_file>\n")
    print("This script will load the csv files,")
    print("and create a detailed report of the specified ASns.")

# main

if __name__ == "__main__":
    time_start = time.time()
    if len(sys.argv) < 3:
        usage()
        exit(-1)

    # parse the arguments
    output_dir = sys.argv[1]
    ASes = []
    argc = 2
    while argc < len(sys.argv) and sys.argv[argc].startswith("AS"):
        ASes.append(sys.argv[argc])
        argc += 1
    if len(ASes) == 0:
        print("No AS specified.")
        usage()
        exit(-1)
    csv_files = sys.argv[argc:]
    if len(ASes) == 0:
        print("No csv file specified.")
        usage()
        exit(-1)

    # load the selected AS from csv files
    detailed_log = detailed_log(ASes)
    for csv_file in csv_files:
        detailed_log.load_csv_log(csv_file)
        print("Loaded: " + csv_file)

    # Look at spread of duplicates per rr tag
    # we want a summary like report, but with on line per query_cc, query_as, rr_type, tags, nb unique ID seen.
    if False:
        for ASn in ASes:
            detailed_report_name = os.path.join(output_dir, "detailed_report_" + ASn + ".csv" )
            df = detailed_log.detailed_report(ASn)
            print("Detailed report for " + ASn + " has " + str(df.shape[0]) + " lines.")
            df.to_csv(detailed_report_name, sep=",")
            print("Saved detailed report as " + detailed_report_name)

    if True:
        subnet_report_name = os.path.join(output_dir, "subnet_details.csv" )
        df = detailed_log.create_flat_report()
        print("Detailed subnet report for has " + str(df.shape[0]) + " lines.")
        df.to_csv(subnet_report_name, sep=",")
        print("Saved detailed subnet report as " + subnet_report_name)