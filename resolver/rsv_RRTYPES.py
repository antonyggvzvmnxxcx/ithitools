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

class RRTypes_all:
    def __init__(self):
        self.rrt = dict()
        self.rru = dict()
        self.total = 0

    def add_query(self, rr_type, uid):
        if not rr_type in self.rrt:
            self.rrt[rr_type] = 0
        self.rrt[rr_type] += 1
        if not rr_type in self.rru:
            self.rru[rr_type] = set()
        if not uid in self.rru[rr_type]:
            self.rru[rr_type].add(uid)

    def load_log(self, saved_file):
        nb_events = 0
        with open(saved_file, newline='') as csvfile:
            rsv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            is_first = True
            is_second = True
            header_row = [ 'rr_type', 'query_user_id' ]
            header_index = [ -1, -1 ]

            for row in rsv_reader:
                if is_first:
                    # print(",".join(row))
                    for i in range(0, len(header_row)):
                        for x in range(0, len(row)):
                            if row[x] == header_row[i]:
                                # print("row[" + str(x) + "](" + str(row[x]) + ") == " + header_row[i])
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
                    rr_type = row[header_index[0]]
                    uid = row[header_index[1]]
                    self.add_query(rr_type, uid)
        return nb_events

    def get_df(self):
        u_https = len(self.rru['HTTPS'])
        u_a = len(self.rru['A'])
        u_aaaa = len(self.rru['AAAA'])
        ad_set = self.rru['A'].union(self.rru['AAAA'])
        ad_both =  self.rru['A'].intersection(self.rru['AAAA'])
        l_ad_both = len(ad_both)
        uu_https = u_https - len(ad_set.intersection(self.rru['HTTPS']))
        uu_a = u_a - l_ad_both
        uu_aaaa = u_aaaa - l_ad_both
        u_all = len(ad_set.union(self.rru['HTTPS']))

        r_https = [ "HTTPS",  self.rrt['HTTPS'], u_https, uu_https, "Unique= only HTTPS, no A or AAAA "]
        r_a = ["A", self.rrt['A'], u_a, uu_a, "Unique= A, no AAAA "]
        r_aaaa = ["AAAA", self.rrt['AAAA'], u_aaaa, uu_aaaa,  "Unique= AAAA, no A"]
        r_tot = [ "Total", self.rrt['HTTPS'] + self.rrt['A'] + self.rrt['AAAA'], u_all, 0, "" ]
        t = [ r_https, r_a, r_aaaa, r_tot ]

        df = pd.DataFrame(t, columns=[ "rr_type", "count", "advertisements", "unique", "what" ])
        return df

def usage():
    print("Usage: python rsv_RRTYPES.py  <output_dir>  <csv_file> ... <csv_file>\n")
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

    log_rr = RRTypes_all()
    for csv_file in csv_files:
        log_rr.load_log(csv_file)
        print("Loaded: " + csv_file)
    
    print("Obtained " + str(len(log_rr.rrt)) + " RR types")

    df = log_rr.get_df()

    rr_file = os.path.join(output_dir, "rr_types.csv" )
    df.to_csv(rr_file)
    print("Report saved.")