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

class IP_nb_bucket:
    def __init__(self):
        self.nb_ip = 0
        self.nb_uid = 0
        self.nb_others = 0
        self.nb_open = 0
        self.nb_both = 0
    def add_ip(self, nb_uid, nb_others, nb_open, nb_both):
        self.nb_ip += 1
        self.nb_uid += nb_uid
        self.nb_others += nb_others
        self.nb_open += nb_open
        self.nb_both += nb_both
    def add_bucket(self, bucket):
        self.nb_ip += bucket.nb_ip
        self.nb_uid += bucket.nb_uid
        self.nb_others += bucket.nb_others
        self.nb_open += bucket.nb_open
        self.nb_both += bucket.nb_both

class CC_AS_IP_data:
    def __init__(self):
        self.others = set()
        self.open = set()

    def add_uid(self, uid, resolver_tag):
        if resolver_tag in rsv_log_parse.tag_public_set:
            if not uid in self.open:
                self.open.add(uid)
        elif not uid in self.others:
            self.others.add(uid)

    def summary(self):
        total_set = self.others.union(self.open)
        both_set = self.others.intersection(self.open)
        return len(total_set), len(self.others), len(self.open), len(both_set)

class CC_AS_data:
    def __init__(self):
        self.ips = dict()
        self.buckets = dict()
        self.total = 0

    def add_ip_uid(self, IP, uid, resolver_tag):
        if not IP in self.ips:
            self.ips[IP] = CC_AS_IP_data()
        self.ips[IP].add_uid(uid, resolver_tag)

    def summary(self):
        self.buckets = dict()
        for IP in self.ips:
            nb_uid, nb_others, nb_open, nb_both = self.ips[IP].summary()
            self.total += nb_uid
            if not nb_uid in self.buckets:
                self.buckets[nb_uid] = IP_nb_bucket()
            self.buckets[nb_uid].add_ip(nb_uid, nb_others, nb_open, nb_both)

    def get_table(self, cc, asn):
        t = []
        for nb_uid in self.buckets:
            r = [ cc, asn, nb_uid,
                 self.buckets[nb_uid].nb_ip,
                 self.buckets[nb_uid].nb_uid,
                 self.buckets[nb_uid].nb_others,
                 self.buckets[nb_uid].nb_open,
                 self.buckets[nb_uid].nb_both ]
            t.append(r)
        return t
       
class CC_data:
    def __init__(self):
        self.cc_as = dict()
        self.buckets = dict()
        self.total = 0

    def add_asn_IP_uid(self, asn, IP, uid, resolver_tag):
        if not asn in self.cc_as:
            self.cc_as[asn] = CC_AS_data()
        self.cc_as[asn].add_ip_uid(IP, uid, resolver_tag)

    def add_cc_as(self, cc_as):
        if not cc_as in self.cc_as:
            self.cc_as[cc_as] = CC_AS_data()

    def summary(self):
        for asn in self.cc_as:
            self.cc_as[asn].summary()
            self.total += self.cc_as[asn].total
            for bucket in self.cc_as[asn].buckets:
                if not bucket in self.buckets:
                    self.buckets[bucket] = IP_nb_bucket()
                self.buckets[bucket].add_bucket(self.cc_as[asn].buckets[bucket])

    def get_table(self, cc, as_limit):
        t = []
        for nb_uid in self.buckets:
            r = [ cc, '--' , nb_uid,
                 self.buckets[nb_uid].nb_ip,
                 self.buckets[nb_uid].nb_uid,
                 self.buckets[nb_uid].nb_others,
                 self.buckets[nb_uid].nb_open,
                 self.buckets[nb_uid].nb_both ]
            t.append(r)
        for asn in self.cc_as:
            if self.cc_as[asn].total >= as_limit:
                ta = self.cc_as[asn].get_table(cc, asn)
                t += ta
        return t


class IP_log_all:
    def __init__(self):
        self.ccs = dict()
        self.buckets = dict()
        self.total = 0

    def add_query(self, cc, asn, IP, uid, resolver_tag):
        if not cc in self.ccs:
            self.ccs[cc] = CC_data()
        self.ccs[cc].add_asn_IP_uid(asn, IP, uid, resolver_tag)

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
                    self.add_query(query_cc, query_AS, query_IP, query_user_id, resolver_tag)
        return nb_events

    
    def summary(self):
        for cc in self.ccs:
            self.ccs[cc].summary()
            self.total += self.ccs[cc].total
            for bucket in self.ccs[cc].buckets:
                if not bucket in self.buckets:
                    self.buckets[bucket] = IP_nb_bucket()
                self.buckets[bucket].add_bucket(self.ccs[cc].buckets[bucket])

    def get_table(self, cc_limit, as_limit):
        t = []
        for nb_uid in self.buckets:
            r = [ '--', '--' , 
                 nb_uid,
                 self.buckets[nb_uid].nb_ip,
                 self.buckets[nb_uid].nb_uid,
                 self.buckets[nb_uid].nb_others,
                 self.buckets[nb_uid].nb_open,
                 self.buckets[nb_uid].nb_both ]
            t.append(r)
        for cc in self.ccs:
            if self.ccs[cc].total >= cc_limit:
                ta = self.ccs[cc].get_table(cc, as_limit)
                t += ta
        return t

def usage():
    print("Usage: python rsv_IP_report.py  <output_dir>  <csv_file> ... <csv_file>\n")
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
    csv_files = sys.argv[2:]

    log_IP = IP_log_all()
    for csv_file in csv_files:
        log_IP.load_IP_log(csv_file)
        print("Loaded: " + csv_file)
    
    print("Obtained " + str(len(log_IP.ccs)) + " CC")

    log_IP.summary()
    for cc in log_IP.ccs:
        print(cc + ": " + str(log_IP.ccs[cc].total))
    print("Total: " + str(log_IP.total) + " uids")

    IP_file = os.path.join(output_dir, "IP_all_report.csv" )

    IP_df = pd.DataFrame(log_IP.get_table(100, 100), columns=[ "cc", "asn", "bucket", "nb_ip", "uids", "isp", "open", "both"])
    IP_df.to_csv(IP_file)
    print("Report saved.")