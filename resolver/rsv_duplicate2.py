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

# New classes
class category_list:
    def __init__(self):
        self.has_dup = 0
        self.has_two = 0
        self.has_3 = 0
        self.more_than_3 = 0
        self.as_plus_group = 0
        self.isp_plus_same_cc = 0
        self.isp_plus_other_cc = 0
        self.isp_plus_google = 0
        self.isp_plus_cloudflare = 0
        self.isp_plus_other = 0
        self.google_plus_cloudflare = 0
        self.google_plus_same_cc = 0
        self.google_plus_other_cc = 0
        self.google_plus_other = 0
        self.cloudflare_plus_other = 0
        self.other_dups = 0

    def add(self, other):
        self.has_dup += other.has_dup
        self.has_two += other.has_two
        self.has_3 += other.has_3
        self.more_than_3 += other.more_than_3
        self.as_plus_group += other.as_plus_group
        self.isp_plus_same_cc += other.isp_plus_same_cc
        self.isp_plus_other_cc += other.isp_plus_other_cc
        self.isp_plus_google += other.isp_plus_google
        self.isp_plus_cloudflare += other.isp_plus_cloudflare
        self.isp_plus_other += other.isp_plus_other
        self.google_plus_cloudflare += other.google_plus_cloudflare
        self.google_plus_same_cc += other.google_plus_same_cc
        self.google_plus_other_cc += other.google_plus_other_cc
        self.google_plus_other += other.google_plus_other
        self.cloudflare_plus_other += other.cloudflare_plus_other
        self.other_dups += other.other_dups

    def headers():
        return [ 'has_dup',
        'has_two',
        'has_3',
        'more_than_3',
        'as_plus_group',
        'isp_plus_same_cc',
        'isp_plus_other_cc',
        'isp_plus_google',
        'isp_plus_cloudflare',
        'isp_plus_other',
        'google_plus_cloudflare',
        'google_plus_same_cc',
        'google_plus_other_cc',
        'google_plus_other',
        'cloudflare_plus_other',
        'other_dups']

    def row(self):
        return ([self.has_dup,
            self.has_two,
            self.has_3,
            self.more_than_3,
            self.as_plus_group,
            self.isp_plus_same_cc,
            self.isp_plus_other_cc,
            self.isp_plus_google,
            self.isp_plus_cloudflare,
            self.isp_plus_other,
            self.google_plus_cloudflare,
            self.google_plus_same_cc,
            self.google_plus_other_cc,
            self.google_plus_other,
            self.cloudflare_plus_other,
            self.other_dups] )

class detail_cc_as_rr_uid:
    def __init__(self, uid):
        self.uid = uid
        self.resolver_tags = dict()

    def add_query(self, resolver_tag):
        if not resolver_tag in self.resolver_tags:
            self.resolver_tags[resolver_tag] = 1
        else:
            self.resolver_tags[resolver_tag] += 1

    # Reduce the categories so we can express dup ratio, from:
    # tag_list = [ 'Same_AS', 'Same_group',  'Cloud', 'Same_CC', 'Other_cc', 'googlepdns', 'cloudflare', \
    #        'opendns', 'quad9', 'level3', 'neustar', 'he' ]
    # tag_isp_set = set(['Same_AS', 'Same_group' ])
    # tag_public_set = set([ 'googlepdns', 'cloudflare', \
    #       'opendns', 'quad9', 'level3', 'neustar', 'he' ])
    def categorize(self):
        cats = category_list()
        has_same_as = False
        has_same_group = False
        has_same_cc = False
        has_other_cc = False
        has_google = False
        has_cloudflare = False
        has_quad9 = False
        has_level3 = False
        has_other = False

        if len(self.resolver_tags) >= 2:
            cats.has_dup = 1
            for tag in self.resolver_tags:
                if tag == 'Same_AS':
                    has_same_as = True
                elif tag == 'Same_group':
                    has_same_group = True
                elif tag == 'Same_CC':
                    has_same_cc = True
                elif tag == 'Other_cc':
                    has_other_cc = True
                elif tag == 'googlepdns':
                    has_google = True
                elif tag == 'cloudflare':
                    has_cloudflare = True
                else:
                    has_other = True
            if len(self.resolver_tags) == 2:
                cats.has_two = 1
                if has_same_as and has_same_group:
                    cats.as_plus_group = 1
                elif has_same_as or has_same_group:
                    if has_same_cc:
                        cats.isp_plus_same_cc = 1
                    elif has_other_cc:
                        cats.isp_plus_other_cc = 1
                    elif has_google:
                        cats.isp_plus_google = 1
                    elif has_cloudflare:
                        cats.isp_plus_cloudflare = 1
                    else:
                        cats.isp_plus_other = 1
                elif has_google:
                    if has_cloudflare:
                        cats.google_plus_cloudflare = 1
                    elif has_same_cc:
                        cats.google_plus_same_cc = 1
                    elif has_other_cc:
                        cats.google_plus_other_cc = 1
                    else:
                        cats.google_plus_other = 1
                elif has_cloudflare:
                    cats.cloudflare_plus_other = 1
                else:
                    cats.other_dups = 1
            else:
                if len(self.resolver_tags) == 3:
                    cats.has_3 = 1
                else:
                    cats.more_than_3 = 1
        return cats

class detail_cc_as_rr:
    def __init__(self, query_cc, query_AS, rr_type):
        self.query_cc = query_cc
        self.query_AS = query_AS
        self.rr_type = rr_type
        # length of self.uids provides number of queries for this CC_AS_RR
        self.uids = dict()
        self.categories = category_list()

    def add_query(self, uid, resolver_tag):
        if not uid in self.uids:
            self.uids[uid] = detail_cc_as_rr_uid(uid)
        self.uids[uid].add_query(resolver_tag)

    def categorize(self):
        self.categories = category_list()
        for uid in self.uids:
            categories = self.uids[uid].categorize()
            self.categories.add(categories)

class detailed_log:
    def __init__(self, rr_list):
        self.cc_as_rrs = dict()
        self.rr_list = rr_list
        if rr_list == []:
            self.rr_list = [ 'A', 'AAAA', 'HTTPS' ]
        self.rr_set = set(self.rr_list)

    def add_query(self, cc, asn, rr_type, resolver_tag, uid):
        cc_as_rr_key = cc + '.' + asn + '.' + rr_type
        if not cc_as_rr_key in self.cc_as_rrs:
            self.cc_as_rrs[cc_as_rr_key] = detail_cc_as_rr(cc, asn, rr_type)
        self.cc_as_rrs[cc_as_rr_key].add_query(uid, resolver_tag)

    def load_csv_log(self, saved_file):
        nb_events = 0
        with open(saved_file, newline='') as csvfile:
            rsv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            is_first = True
            is_second = True
            header_row = [ 'resolver_tag', 'query_cc', 'query_AS', 'query_user_id', 'rr_type' ]
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

                    resolver_tag = row[header_index[0]]
                    #if not resolver_tag in self.tag_check:
                    #    print("Unexpected tag: " + resolver_tag + " in:\n" + ",".join(row))
                    #    exit(-1)
                    query_cc = row[header_index[1]]
                    query_AS = row[header_index[2]]
                    uid = row[header_index[3]]
                    rr_type = row[header_index[4]]
                    #if not rr_type in self.rr_check:
                    #    print("Unexpected rr: " + rr_type + " in:\n" + ",".join(row))
                    #    exit(-1)
                    if rr_type in self.rr_set:
                        self.add_query(query_cc, query_AS, rr_type, resolver_tag, uid)
                    nb_events += 1
        return nb_events

    # create a report of duplicates, with 1 line per As per rrtype, and a summary line.
    def dup_report(self):
        headers = [ 'query_cc', 'query_AS', 'rr_type', 'nb_uids' ]
        headers += category_list.headers()
        report_list = []
        for cc_as_rr_key in self.cc_as_rrs:
            self.cc_as_rrs[cc_as_rr_key].categorize()
            report_row = [ self.cc_as_rrs[cc_as_rr_key].query_cc, \
                self.cc_as_rrs[cc_as_rr_key].query_AS, \
                self.cc_as_rrs[cc_as_rr_key].rr_type, \
                len(self.cc_as_rrs[cc_as_rr_key].uids) ]
            report_row += self.cc_as_rrs[cc_as_rr_key].categories.row()
            report_list.append(report_row)
        df = pd.DataFrame(report_list,columns=headers)
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

    # load the high duplicate AS from csv files
    dup_logs = detailed_log([ 'A' ])
    for csv_file in csv_files:
        nb_events = dup_logs.load_csv_log(csv_file)
        print("Loaded " + str(nb_events) + " from " + csv_file)


    # Look at spread of duplicates per rr tag
    # we want a summary like report, but with on line per query_cc, query_as, rr_type, tags, nb unique ID seen.
    dup_report_name = os.path.join(output_dir, "duplicate_report.csv" )
    df = dup_logs.dup_report()
    print("Dup report has " + str(df.shape[0]) + " lines.")
    df.to_csv(dup_report_name, sep=",")
    print("Saved dup report as " + dup_report_name)

