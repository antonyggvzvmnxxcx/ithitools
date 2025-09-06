# Study of query IP addresses.
# the report has a line per <query_cc, query_AS, query_IP, nb_uids>
# where nb_uids is the number of unique UIDs seen for the IP address

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


def parse_cc_as_IP_key(key):
    query_cc = key[0:2]
    as_plus_IP = key[2:].split("_")
    query_AS = as_plus_IP[0]
    if len(as_plus_IP) > 0:
        query_IP = as_plus_IP[1]
    else:
        query_IP = ""
    return query_cc, query_AS, query_IP

def get_cc_as_IP_key(query_cc, query_AS, query_IP):
    key = query_cc + query_AS + '_' + query_IP
    return key

class IP_data:
    def __init__(self):
        self.uids = set()
        self.dups = set()
        self.resolver_tags = dict()

    def add_uid(self, uid, resolver_tag):
        if not resolver_tag in self.resolver_tags:
            self.resolver_tags[resolver_tag] = set()
        if not uid in self.resolver_tags[resolver_tag]:
            self.resolver_tags[resolver_tag].add(uid)
            if not uid in self.uids:
                self.uids.add(uid)
            elif not uid in self.dups:
                self.dups.add(uid)

    def get_headers():
        headers = [ 'query_cc', 'query_AS', 'query_IP', 'nb_uids', 'nb_dups' ]
        for tag in rsv_log_parse.tag_list:
            headers.append(tag)
        return headers

    def get_row(self,key):
        query_cc, query_AS, query_IP = parse_cc_as_IP_key(key)

        key_row = [ query_cc, query_AS, query_IP, len(self.uids), len(self.dups) ]
        for tag in rsv_log_parse.tag_list:
            w_tag = 0
            if tag in self.resolver_tags:
                w_tag = len(self.resolver_tags[tag])
            key_row.append(w_tag)
        return key_row

class IP_log:
    def __init__(self, as_list):
        self.as_set = set(as_list)
        self.cc_as_IP = dict()

    def add_query(self, key, query_user_id, resolver_tag):
        if not key in self.cc_as_IP:
            self.cc_as_IP[key] = IP_data()
        self.cc_as_IP[key].add_uid(query_user_id, resolver_tag)

    def load_IP_log(self, saved_file):
        nb_events = 0
        with open(saved_file, newline='') as csvfile:
            rsv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            is_first = True
            is_second = True
            header_row = [ 'query_cc', 'query_AS', 'query_IP', 'query_user_id', 'resolver_tag' ]
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
                    query_cc = row[header_index[0]]
                    query_AS = row[header_index[1]]
                    query_IP = row[header_index[2]]
                    query_user_id = row[header_index[3]]
                    resolver_tag = row[header_index[4]]
                    if not query_AS in self.as_set:
                        continue
                    key = get_cc_as_IP_key(query_cc, query_AS, query_IP)
                    self.add_query(key, query_user_id, resolver_tag)
        return nb_events


    def create_IP_report(self):
        # prepare the headers
        headers = IP_data.get_headers()
        # prepare the keys
        keys = list(self.cc_as_IP.keys())
        keys.sort()
        # prepare the report
        IP_list = []
        for key in keys:
            key_row = self.cc_as_IP[key].get_row(key)
            IP_list.append(key_row)
        IP_df = pd.DataFrame(IP_list, columns=headers)
        return IP_df

def usage():
    print("Usage: python rsv_IP_report.py  <output_dir> *<ASnnn>  <csv_file> ... <csv_file>\n")
    print("This script will load the csv files,")
    print("and create an IP list for the specified ASns.")

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
    log_IP = IP_log(ASes)
    for csv_file in csv_files:
        log_IP.load_IP_log(csv_file)
        print("Loaded: " + csv_file)
    
    print("Obtained " + str(len(log_IP.cc_as_IP)) + " IP addresses.")

    IP_file = os.path.join(output_dir, "IP_report.csv" )
    IP_df = log_IP.create_IP_report()
    IP_df.to_csv(IP_file)
    print("Report saved.")