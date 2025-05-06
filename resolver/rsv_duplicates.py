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

class detail_cc_as:
    def __init__(self, key):
        self.rr_types = dict()
        self.uids = dict()
        self.query_cc = key[0:2]
        self.query_AS = key[2:]
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
        self.cc_ases = dict()
        for key in as_list:
            self.cc_ases[key] = detail_cc_as(key)
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
            header_row = [ 'query_time', 'resolver_tag', 'query_cc', 'query_AS', 'query_user_id', 'resolver_IP', 'resolver_AS', 'rr_type' ]
            header_index = [ -1, -1, -1, -1, -1,  -1,  -1, -1 ]

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
                    #if not rr_type in self.rr_check:
                    #    print("Unexpected rr: " + rr_type + " in:\n" + ",".join(row))
                    #    exit(-1)
                    self.add_query(key, rr_type, resolver_tag, uid, query_time, resolver_IP, resolver_AS)
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
    def dup_report(self):
        headers = [ 'query_cc', 'query_AS', 'rr_type', 'nb_uids', 'nb_dups' ]
        report_list = []
        for tag in rsv_log_parse.tag_list:
            headers.append(tag)
        for key in self.cc_ases:
            # initialize the per tag total
            query_cc = key[0:2]
            query_AS = key[2:]
            ccas_report_tags = dict()
            ccas_dup_uids = set()
            ccas_uids = set()
            for rr_type in self.cc_ases[key].rr_types:
                rr_report_tags = dict()
                rr_dups_uids = set()
                rr_uids = set()
                # initialize the per tag total for this rr_type
                for resolver_tag in self.cc_ases[key].rr_types[rr_type].q_tags:
                    #if not resolver_tag in self.tag_check:
                    #    print("Unexpected tag: " + resolver_tag + " in:\n" + key + "/" + rr_type)
                    #    exit(-1)                  
                    if not resolver_tag in rr_report_tags:
                        rr_report_tags[resolver_tag] = set()
                        if not resolver_tag in ccas_report_tags:
                            ccas_report_tags[resolver_tag] = set()
                    for uid in self.cc_ases[key].rr_types[rr_type].q_tags[resolver_tag].q_uids:
                        if not uid in rr_uids:
                            rr_uids.add(uid)
                            if not uid in ccas_uids:
                                ccas_uids.add(uid)
                        if len(self.cc_ases[key].uids[uid]) > 1:
                            #add 1 for the count of uid in the per-RR total
                            if not uid in rr_report_tags[resolver_tag]:
                                rr_report_tags[resolver_tag].add(uid)
                            if not uid in ccas_report_tags[resolver_tag]:
                                ccas_report_tags[resolver_tag].add(uid)
                            if not uid in rr_dups_uids:
                                rr_dups_uids.add(uid)
                                if not uid in ccas_dup_uids:
                                    ccas_dup_uids.add(uid)
                # print the per AS+rr_type report
                report = [ query_cc, query_AS, rr_type, len(rr_uids), len(rr_dups_uids) ]
                for resolver_tag in rsv_log_parse.tag_list:
                    tag_uid_count = 0
                    if resolver_tag in rr_report_tags:
                        tag_uid_count = len(rr_report_tags[resolver_tag])
                    report.append(tag_uid_count)
                report_list.append(report)
            # produce the per_AS report    
            report = [ query_cc, query_AS, 'total', len(ccas_uids), len(ccas_dup_uids) ]
            for resolver_tag in rsv_log_parse.tag_list:
                tag_uid_count = 0
                if resolver_tag in ccas_report_tags:
                    tag_uid_count = len(ccas_report_tags[resolver_tag])
                report.append(tag_uid_count)
            report_list.append(report)
        df = pd.DataFrame(report_list,columns=headers)
        return df

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

    def get_random_queries(self, n_rand, forced_keys, n_per_forced_key):
        select_keys = set(forced_keys)
        uid_list = []
        selected_list = []
        # first, accumulate a global dict of keys and sample N out of it
        for key in self.cc_ases:
            if not key in select_keys:          
                for uid in self.cc_ases[key].uids:
                    if len(self.cc_ases[key].uids[uid]) > 1:
                        uid_list.append([key,uid])
        selected_list = random.sample(uid_list, n_rand)
        # add random uids picked from the forced keys
        for key in forced_keys:
            forced_dup_uid = []
            for uid in self.cc_ases[key].uids:
                if len(self.cc_ases[key].uids[uid]) > 1:
                    forced_dup_uid.append([key, uid])
            if len(forced_dup_uid) > n_per_forced_key:
                selected_list += random.sample(forced_dup_uid, n_per_forced_key)
            else:
                selected_list += forced_dup_uid
        # build a table with all uids for the selected list
        t = []
        for key_uid in selected_list:
            t += self.extract_queries(key_uid[0], key_uid[1])
        df = pd.DataFrame(t, columns=[ 'query_cc', 'query_AS', 'uid', 'query_time', 'time_from_first', 'rr_type', 'resolver_tag', 'resolver_AS', 'resolver_IP' ])
        return df

def usage():
    print("Usage: python rsv_duplicates.py <output_dir> <csv_file> ... <csv_file>\n")
    print("This script will load the csv files,")
    print("and create a detailed report of CC/AS with most duplicates.")

# main

if __name__ == "__main__":
    time_start = time.time()
    if len(sys.argv) < 3:
        usage()
        exit(-1)

    output_dir = sys.argv[1]
    csv_files = sys.argv[2:]

    # first, load the summary file.

    summary_file_name = os.path.join(output_dir, "summary.csv" )
    as_dups, as_reps = extract_AS_from_summary(summary_file_name, threshold=10000)
    if len(as_dups) < 10:
        # probably a test!
        # redo with lower threshold
        as_dups, as_reps = extract_AS_from_summary(summary_file_name, threshold=100)

    # add three reprsentatives AS to as_dup:
    # Comcast: US/AS7922
    # Orange: FR/AS3215
    # Claro: BR/AS28573

    forced_keys = [ 'USAS7922', 'FRAS3215', 'BRAS28573' ]
    dup_set = set(as_dups)
    for x in forced_keys:
        if not x in dup_set:
            as_dups.append(x)
    print("Selected " + str(len(as_dups)) + " CC/AS from " + summary_file_name)

    # load the high duplicate AS from csv files
    dup_logs = detailed_log(as_dups)
    for csv_file in csv_files:
        dup_logs.load_csv_log(csv_file)
        print("Loaded: " + csv_file)

    # for debugging, look at most used IP in AS0
    as0_report_name = os.path.join(output_dir, "as0_report.csv" )
    adf = dup_logs.as0_report()
    print("As0 report has " + str(adf.shape[0]) + " lines.")
    adf.to_csv(as0_report_name, sep=",")
    print("Saved as0 report as " + as0_report_name)


    # Look at spread of duplicates per rr tag
    # we want a summary like report, but with on line per query_cc, query_as, rr_type, tags, nb unique ID seen.
    dup_report_name = os.path.join(output_dir, "dup_report.csv" )
    df = dup_logs.dup_report()
    print("Dup report has " + str(df.shape[0]) + " lines.")
    df.to_csv(dup_report_name, sep=",")
    print("Saved dup report as " + dup_report_name)


    # we also want to look at a variety of individuals UID, taken by preference from the duplicate set
    # we will select 5 each from the classic ISP (Comcast, Orange, Claro), and then 50 taken at random from
    # the set of duplicates
    sample_queries_name = os.path.join(output_dir, "sample_queries.csv" )
    qdf = dup_logs.get_random_queries(50, forced_keys, 5)
    print("Queries sample has " + str(qdf.shape[0]) + " lines.")
    qdf.to_csv(sample_queries_name, sep=",")
    print("Saved queries sample as " + sample_queries_name)

