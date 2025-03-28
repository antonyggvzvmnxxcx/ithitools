# Parsing of the APNIC resolver data  file.
#
# here's a sample record:
#
#
# 1730419200.001728 client 172.68.246.89#37826: query: 0du-results-uf8c998ed-c233-a1ef2-s1730419189-i00000000-0.am.dotnxdomain.net. IN DS -ED () 1914810962 0
#
# Field 1 - time the query was received by the auth server
# Field 2 - the word "client"
# Field 3 - the source IP address and port number (i.e. the IP address of the recursive resolver that passed us the query)
# Field 4- the word "query"
# Field 5 - The query name (see below)
# Field 6 - The Query class ("IN")
# Field 7 - the Query type (in this case DS)
# Field 8 - EDNS values E = EDNS, D = DNSSEC OK If client subnet is being used it is found here (e.g. "IN HTTPS -EDS6/56/0|2001:56a:7636:6e00::2000:0 () 1914810962 0")
#
# The query name is a sequence of fields delineated by a hyphen
#
# 0du-u0b7cf17d-c13-a04C5-s1730796660-i6e8d88e1-0.ap.dotnxdomain.net
#
# 1. Experiment codes 0du
#
# 0du - dual stack, not signed with DNSSEC
# 04u - V4 only resource record, not signed with DNSSEC
# 06u - V4 only resource record, not signed with DNSSEC
# 0ds - dual stack - dnssec signed
# 0di - dual stack, invalid DNSSEC signature
# fdu - dual stack - always returns servfail response code
# 
# I suggest ignoring all else and just look at 0du and fdu entries
# 
# 2. User identifier - u0b7cf17da hex-encoded uuid value. 
# 
# All queries with a common user identifier value were from the same initial ad presentation.
# 
# 3. COuntry code - c13
# 
# 
# The country where the end user is located. 13 is Country AU = Australia
# The table of country codes is in TABLE 1.
#
# 4. Origin AS - a04C5
# 
# The hex value of the origin AS - hex 4c5 is 1221
# 
# 5 - time of ad generation - s1730796660
# 
# unix timestamp value (seconds since 1 Jan 1970)
# 
# 
# 6 - IPv4 address of client - i6e8d88e1
#
# IF the ad was originally delivered using IPv4 (and many are not) then the
# ipv4 address of the client is encoded here in hex
# 
# 6e8d88e1 = 110.141.135.225

import ipaddress
from math import nan
from ssl import ALERT_DESCRIPTION_DECRYPT_ERROR
import country
import traceback
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import ip2as
import open_rsv
import bz2
import time
import top_as
import csv

class rsv_log_line:
    def __init__(self):
        self.query_time = 0.0
        self.resolver_IP = "0.0.0.0"
        self.resolver_port = 0
        self.resolver_AS = ""
        self.resolver_cc = ""
        self.resolver_tag = ""
        self.query_experiment = ""
        self.query_user_id = ""
        self.query_cc = ""
        self.query_AS = ""
        self.query_ad_time = 0
        self.query_ip = ""
        self.rr_class = ""
        self.rr_type = ""
        self.query_edns = ""
        self.is_results = False
        self.is_anomalous = False
        self.is_cretinous = False
        self.is_starquery = False
        self.invalid_query = ""
        self.server = ""

    def parse_query_name_params(self, query_parts, query_name):
        is_valid = True
        self.query_experiment = query_parts[0]
        if query_parts[1] == "results":
            self.is_results = True
            query_parts = query_parts[1:]
        self.query_user_id = query_parts[1]

        self.query_cc = country.country_code_from_c999(query_parts[2])

        query_AS_str = query_parts[3]
        if query_AS_str.startswith("a"):
            as_num = int(query_AS_str[1:], 16)
            self.query_AS = "AS" + str(as_num)
            as_parsed = 1
        else:
            #print("Bad AS:" + query_name )
            self.query_AS = "AS0"
            as_parsed = 0
        ad_time_str = query_parts[3+as_parsed]
        if ad_time_str.startswith("s"):
            self.query_ad_time = int(ad_time_str[1:])
        else:
            print("Bad Time:" + query_name )
            is_valid = False
        query_ip_str = query_parts[4+as_parsed]
        if query_ip_str.startswith("i"):
            ip_num = int(query_ip_str[1:], 16)
            self.query_ip = str(ip_num>>24)+ "." + \
                str((ip_num>>16)&255)+ "." + \
                str((ip_num>>8)&255)+ "." + \
                str(ip_num&255)
        else:
            print("Bad IP:" + query_name )
            is_valid = False
        return is_valid

    def parse_query_name_anomalous(self, query_parts):
        #query: 000-000-000a-0000-0006-e7b5bab7-233-a55A8-1736378116-ac380eb6-0
        # query: 04u-uf8c0aa51-c185-a40625-s1730422799-iaa54ac12-0
        is_valid = True
        if len(query_parts) < 10:
            return False
        delimiter = "-"
        self.query_experiment = delimiter.join(query_parts[:5])
        self.query_user_id = query_parts[5]
        self.query_cc = country.country_code_from_c999("c" + query_parts[6])
        query_AS_str = query_parts[7]
        if query_AS_str.startswith("a"):
            as_num = int(query_AS_str[1:], 16)
            self.query_AS = "AS" + str(as_num)
            as_parsed = 1
        else:
            print("Bad AS:" + query_AS_str )
            is_valid = False
        self.query_ad_time = int(query_parts[8])
        ip_num = int(query_parts[9], 16)
        self.query_ip = str(ip_num>>24)+ "." + \
            str((ip_num>>16)&255)+ "." + \
            str((ip_num>>8)&255)+ "." + \
            str(ip_num&255)
        return is_valid

    def parse_query_name_sentinel(self, query_parts):
        #query: root-key-sentinel-is-ta-20326.0ds-uec321a73-c233-s1536509491-icff1e56f-2
        pass
        
    def parse_query_name(self, query_name):
        is_valid = True
        query_name = query_name.strip()
        name_parts = query_name.split(".")
        if len(name_parts[-1]) == 0:
            name_parts = name_parts[:-1]
        if len(name_parts) < 3:
            delimiter = "."
            self.server = delimiter.join(name_parts)
        else:
            delimiter = "."
            self.server = delimiter.join(name_parts[-3:])
        query_string = name_parts[0]
        query_parts = query_string.split("-")
        if query_string.startswith("000-000-000"):
            self.is_anomalous = True
            is_valid = self.parse_query_name_anomalous(query_parts)
        elif query_string.startswith("root-key-sentinel"):
            self.query_experiment = "root-key-sentinel"
            self.is_cretinous = True
        elif len(query_parts) < 6:
            if self.server.endswith(".starnxdomain.net"):
                self.is_starquery = True
            else:
                self.is_cretinous = True
                self.invalid_query = query_string
        else:
            is_valid = self.parse_query_name_params(query_parts, query_name)
        return is_valid

    def parse_line(self, s):
        is_valid = False
        s = s.strip()
        parts = s.split(" ")
        if len(parts) >= 8 and \
            parts[1] == "client" and \
            parts[3] == "query:":
            try:
                self.query_time = float(parts[0])
                # parse IP and port
                ip_ports_str = parts[2]
                if ip_ports_str.endswith(":"):
                    ip_ports_str = ip_ports_str[:-1]
                ip_ports = ip_ports_str.split("#")
                self.resolver_IP = ip_ports[0]
                self.resolver_port = int(ip_ports[1])
                # parse the query class and type
                self.rr_class = parts[5]
                self.rr_type = parts[6]
                # parse the EDNS data
                delimiter = " "
                self.query_edns = delimiter.join(parts[7:])
                # parse the query name
                is_valid = self.parse_query_name(parts[4])
            except Exception as exc:
                traceback.print_exc()
                print('\nCode generated an exception: %s' % (exc))
                print("Cannot parse:\n" + s + "\n")
                is_valid = False
        return is_valid

    # The filter function applies common filters:
    # - query time at most 10 second later than ad time
    # - rr_class = [ "odu" ]
    # - rr_types = [ "A", "AAAA" ]
    # - is_results = False
    # - query_ASes = [] (could be a specific set of ASes)
    def filter(self, query_delay=10, experiment=["0du"], rr_types=["A", "AAAA"], is_results=[False], query_ASes={}):
        filter_OK = True
        if query_delay > 0:
            qd = int(self.query_time) - self.query_ad_time
            filter_OK = (qd <= query_delay)

        if filter_OK and len(experiment) > 0:
            filter_OK = False
            for ex in experiment:
                if ex == self.query_experiment:
                    filter_OK = True
                    break
        if filter_OK and len(rr_types) > 0:
            filter_OK = False
            for qt in rr_types:
                if qt == self.rr_type:
                    filter_OK = True
                    break
        if filter_OK and len(is_results) > 0:
            filter_OK = False
            for ir in is_results:
                if ir == self.is_results:
                    filter_OK = True
                    break
        if filter_OK and len(query_ASes) > 0:
            filter_OK = self.query_AS in query_ASes
        return filter_OK
    
    # set_resolver_AS checks the AS number associated with the source address
    # of the query, and the country code for that AS. Using the source address
    # and the AS number, it find whether this matches an "open resolver".
    # If it does not, it sets the "same AS" flag, and if this is False it
    # sets the "same CC" flag.
    #
    # The additional arguments are the table mapping IPv4 addresses
    # to ASes (ip2a4), IPv6 addresses to (ip2a6) and the AS number
    # to a CC (as_table)
    def set_resolver_AS(self, ip2a4, ip2a6, as_table):
        parts6 = self.resolver_IP.split(":")
        if len(parts6) > 1:
            asn = ip2a6.get_asn(self.resolver_IP)
        else:
            asn = ip2a4.get_asn(self.resolver_IP)
        self.resolver_AS = "AS" + str(asn)
        self.resolver_cc = as_table.cc(self.resolver_AS)
        self.resolver_tag = open_rsv.get_open_rsv(self.resolver_IP, self.resolver_AS)
        if len(self.resolver_tag) == 0:
            if self.resolver_AS == self.query_AS:
                self.resolver_tag = "Same_AS"
            elif top_as.as_group(self.resolver_AS) == top_as.as_group(self.query_AS):
                self.resolver_tag = "Same_group"
            elif self.resolver_AS in top_as.CloudAS:
                self.resolver_tag = "Cloud"
            elif self.resolver_cc == self.query_cc:
                self.resolver_tag = "Same_CC"
            else:
                self.resolver_tag = "Other_cc"

    # debugging function when we want to verify that parsing works as expected.
    def pretty_string(self):
        r = ""
        a = ""
        c = ""
        q = ""
        if self.is_results:
            r = "R"
        if self.is_anomalous:
            a = "A"
        if self.is_cretinous:
            c = "C"
        if self.is_starquery:
            q = "S"

        s = str(self.query_time) + ", " + \
            self.resolver_IP + ", " + \
            str(self.resolver_port) + ", " + \
            self.query_experiment + ", " + \
            self.query_user_id + ", " + \
            self.query_cc + ", " + \
            self.query_AS + ", " + \
            str(self.query_ad_time) + ", " + \
            self.query_ip + ", " + \
            self.rr_class  + ", " + \
            self.rr_type  + ", " + \
            self.server  + ", " + \
            r  + ", " + \
            a  + ", " + \
            c  + ", " + \
            q  + ", " + \
            "\"" + self.query_edns + "\", " + \
            self.invalid_query
        return s
    
    # Headers and row function are useful if one wants to produce a panda
    # data frame that has one line per filetered evennt in the frame.
    def header():
        header = [ 'query_time', \
            'resolver_IP', \
            'resolver_port', \
            'resolver_AS', \
            'resolver_tag', \
            'resolver_cc', \
            'experiment_id', \
            'query_user_id', \
            'query_cc', \
            'query_AS', \
            'query_ad_time', \
            'query_IP', \
            'rr_class', \
            'rr_type', \
            'server', \
            'is_result', \
            'is_anomalous', \
            'is_cretinous', \
            'is_starquery', \
            'query_edns', \
            'invalid_query' ]
        return header

    def row(self):
        r = [ self.query_time, \
            self.resolver_IP, \
            self.resolver_port, \
            self.resolver_AS, \
            self.resolver_tag, \
            self.resolver_cc, \
            self.query_experiment, \
            self.query_user_id, \
            self.query_cc, \
            self.query_AS, \
            self.query_ad_time, \
            self.query_ip, \
            self.rr_class, \
            self.rr_type, \
            self.server, \
            self.is_results, \
            self.is_anomalous, \
            self.is_cretinous, \
            self.is_starquery, \
            self.query_edns , \
            self.invalid_query ]
        return r

# pivot per query and per AS, produce a dictionary with
# one table per AS, containing the queries for that AS

tag_list = [ 'Same_AS', 'Same_group',  'Cloud', 'Same_CC', 'Other_cc', 'googlepdns', 'cloudflare', \
            'opendns', 'quad9', 'level3', 'neustar', 'he' ]
tag_isp_set = set(['Same_AS', 'Same_group' ])
tag_public_set = set([ 'googlepdns', 'cloudflare', \
            'opendns', 'quad9', 'level3', 'neustar', 'he' ])
color_list = [ 'blue', 'cyan', 'olive', 'green', 'orange', 'red',  'purple', \
             'brown', 'pink', 'gray', 'yellow', 'violet', 'magenta', 'lime', 'chartreuse', 'salmon' ]
dot_headers = [ 'rsv_type', 'rank', 'first_time', 'delay' ]

class pivoted_record:
    # Record is created for the first time an event appears in an AS record.    
    def __init__(self, qt, tag, query_cc, query_AS, uid):
        self.query_cc = query_cc
        self.query_AS = query_AS
        self.query_user_id = uid
        self.first_tag = tag
        self.first_time = qt
        self.rsv_times = dict()
        self.rsv_times[tag] = qt
        self.delta_times = dict()
        self.has_isp = False
        self.has_public = False

    # add event records a new event after the tag has been created
    def add_event(self, x):
        qt = x['query_time']
        tag = x['resolver_tag']
        if (not tag in self.rsv_times) or \
            qt < self.rsv_times[tag]:
            self.rsv_times[tag] = qt
        if qt < self.first_time:
            self.first_tag = tag
            self.first_time = qt
    
    def add_event2(self, qt, tag):
        if (not tag in self.rsv_times) or \
            qt < self.rsv_times[tag]:
            self.rsv_times[tag] = qt
        if qt < self.first_time:
            self.first_tag = tag
            self.first_time = qt

    # delta time is computed once all events are recorded
    # We only consider the events that happen less that "delta_max"
    # (default= 0.5 second) from the first event. This cuts down the
    # noise of, for example, queries repeated to maintain a cache
    def compute_delta_t(self, delta_max = 0.5):
        for tag in self.rsv_times:
            delta_t = self.rsv_times[tag] - self.first_time
            if delta_t <= delta_max:
                self.delta_times[tag] = delta_t
                if tag in tag_isp_set:
                    self.has_isp = True
                elif tag in tag_public_set:
                    self.has_public = True
                #else:
                #    if (tag != 'Cloud') and (tag !=  'Same_CC') and (tag != 'Other_cc'):
                #        print("Other tag: " + tag)

class subnet_record:
    def __init__(self, query_cc, query_AS, resolver_AS, subnet, count):
        self.query_cc = query_cc
        self.query_AS = query_AS
        self.resolver_AS = resolver_AS
        self.subnet = str(subnet)
        self.count = count

    def headers():
        return [ "query_cc", "query_AS", "resolver_AS", "subnet", "count" ]

    def key(query_cc, query_AS, resolver_AS, subnet):
        return query_cc + query_AS + "_" + resolver_AS  + "_" + str(subnet)

    def subnet_row(self):
        return [
            self.query_cc,
            self.query_AS,
            self.resolver_AS,
            self.subnet,
            self.count ]

class pivoted_cc_AS_record:
    def __init__(self, query_cc,query_AS):
        self.query_cc = query_cc
        self.query_AS = query_AS
        self.rqt = dict()
        self.user_ids = set()
        self.nb_isp = 0
        self.nb_public = 0
        self.nb_both = 0
        self.nb_others = 0
        self.nb_tag_uid = 0
        self.nb_all = 0
        self.subnets = dict()

    # process event 
    # For each UID, we compute a pivoted record, which contains a dict() of "tags".
    # If a tag is present in the dict, we only retain the earliest time for that ta
    def process_event(self, qt, tag, query_cc, query_AS, uid, resolver_IP, resolver_AS):
        self.nb_all += 1
        if uid in self.rqt:
            if not tag in self.rqt[uid].rsv_times:
                self.nb_tag_uid += 1
            self.rqt[uid].add_event2(qt, tag)
        else:
            self.nb_tag_uid += 1
            self.rqt[uid] = pivoted_record(qt, tag, query_cc, query_AS, uid)
            if not uid in self.user_ids:
                self.user_ids.add(uid)

        if tag in tag_isp_set:
            try:
                addr = ipaddress.ip_address(resolver_IP)
                if addr.version == 6:
                    subnet = ipaddress.IPv6Network(resolver_IP + "/40", strict=False)
                else:
                    subnet = ipaddress.IPv4Network(resolver_IP + "/16", strict=False)
                key = subnet_record.key(query_cc, query_AS, resolver_AS, subnet)
                if key in self.subnets:
                    self.subnets[key].count += 1
                else:
                    self.subnets[key] = subnet_record(query_cc, query_AS, resolver_AS, subnet, 1)
            except Exception as exc:
                traceback.print_exc()
                print('\nCode generated an exception: %s' % (exc))
                print("Bad address or subnet:" + resolver_IP + "\n")
    
    # Delta updates the per query record to compute the delta between the
    # arrival in a given category and the first query for that UID.
    # This computation can only be performed once all records have been logged.
    def compute_delta_t(self, delta_max = 0.5):
        for key in self.rqt:
            self.rqt[key].compute_delta_t(delta_max=delta_max)
            if self.rqt[key].has_public:
                if self.rqt[key].has_isp:
                    self.nb_both += 1
                else:
                    self.nb_public += 1
            elif self.rqt[key].has_isp:
                self.nb_isp += 1
            else:
                self.nb_others += 1

    # Produce a one line summary record for the ASN   
    # Return a list of values:
    # r[0] = CC
    # r[1] = ASN
    # r[2] = total number of UIDs
    # r[3] = total number of queries over all (includes repeat)
    # r[4] = total number of tags (one per query and "tag")
    # r[4] = total number of ISP only queries
    # r[5] = total number of public DNS only queries
    # r[6] = total number of queries served by both ISP and public DNS
    # r[7] = total number of queries not served by either ISP or public DNS
    # r[8]..[5+N] = total number of queries served by a given category

    def get_summary(self, first_only):
        if not isinstance(self.query_cc, str) or \
            len(self.query_cc) > 2:
            self.query_cc = 'ZZ'
        
        r = [
            self.query_cc,
            self.query_AS,
            len(self.user_ids),
            self.nb_tag_uid,
            self.nb_all,
            self.nb_isp,
            self.nb_public,
            self.nb_both,
            self.nb_others
        ]
        rank0 = len(r)
        for tag in tag_list:
            r.append(0)

        for key in self.rqt:
            rqt_r = self.rqt[key]
            rank = rank0
            for tag in tag_list:
                if tag in rqt_r.rsv_times:
                    r[rank] += 1
                rank += 1
                
        return r

    # get_delta_t_both:
    # we produce a list of "dots" records suitable for statistics and graphs
    def get_delta_t_both(self):
        dots = []
        for key in self.rqt:
            rqt_r = self.rqt[key]
            if len(rqt_r.delta_times) == 0:
                rqt_r.compute_delta_times()
            n_both = 0
            for tag in rqt_r.delta_times:
                n_both += 1
                dot_line = [ tag, n_both,  rqt_r.first_time, rqt_r.delta_times[tag]]
                dots.append(dot_line)
        dot_df = pd.DataFrame(dots,columns=dot_headers)
        return dot_df

    def get_subnets(self):
        snts = []
        for key in self.subnets:
            snts.append(self.subnets[key].subnet_row())
        snts.sort(key=lambda x: x[4], reverse=True)
        return snts

class pivoted_per_query:
    def __init__(self):
        self.cc_AS_list = dict()
        self.tried = 0

    def process_event(self, qt, tag, query_cc, query_AS, uid, resolver_IP, resolver_AS):
        key = str(query_cc) + str(query_AS)
        if not key in self.cc_AS_list:
            self.cc_AS_list[key] = pivoted_cc_AS_record(query_cc,query_AS)

        self.cc_AS_list[key].process_event(qt, tag, query_cc, query_AS, uid, resolver_IP, resolver_AS)

    def quicker_load(self, file_name, ip2a4, ip2a6, as_table, rr_types=[], experiment=[], query_ASes=[], log_threshold = 15625, time_start=0):
        nb_events = 0
        lth = log_threshold;
        
        filtering = len(rr_types) > 0 or len(experiment) > 0 or len(query_ASes) > 0
        q_set = set(query_ASes)

        if file_name.endswith(".bz2"):
            F = bz2.open(file_name, "rt")
        else:
            F = open(file_name, "r")
        for line in F:
            parsed = True
            try:
                x = rsv_log_line()
                parsed = x.parse_line(line)
            except Exception as exc:
                traceback.print_exc()
                print('\nCode generated an exception: %s' % (exc))
                print("Cannot parse:\n" + line + "\n")
                parsed = False
            if parsed:
                if (not filtering) or x.filter(rr_types=rr_types, experiment=experiment, query_ASes=q_set):
                    x.set_resolver_AS(ip2a4, ip2a6, as_table)
                    self.process_event(x.query_time, x.resolver_tag, x.query_cc, x.query_AS, x.query_user_id, x.resolver_IP, x.resolver_AS)
                    nb_events += 1
                    if (nb_events%lth) == 0:
                        if time_start > 0:
                            time_n = time.time()
                            print("loaded " + str(nb_events) + " events at " + str(time_n - time_start))
                        else:
                            print("loaded " + str(nb_events) + " events.")
                        lth *= 2
                    
        return nb_events

    def load_df_row(self, x):
        self.process_event(x['query_time'], x['resolver_tag'], x['query_cc'], x['query_AS'], x['query_user_id'], x['resolver_IP'], x['resolver_AS'])

    def load_csv_log(self, saved_file):
        #df = pd.read_csv(saved_file)
        #df.apply(lambda x: self.load_df_row(x), axis=1)
        #return df.shape[0]
        nb_events = 0
        with open(saved_file, newline='') as csvfile:
            rsv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            is_first = True
            is_second = True
            header_row = [ 'query_time', 'resolver_tag', 'query_cc', 'query_AS', 'query_user_id', 'resolver_IP', 'resolver_AS' ]
            header_index = [ -1, -1, -1, -1, -1,  -1,  -1 ]

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
                    self.process_event(float(row[header_index[0]]), row[header_index[1]], row[header_index[2]], 
                                       row[header_index[3]], row[header_index[4]], row[header_index[5]],
                                       row[header_index[6]])
                    nb_events += 1
        return nb_events

    def key_list(self):
        return list(self.cc_AS_list.keys())

    def compute_delta_t(self):
        for key in self.cc_AS_list:
            self.cc_AS_list[key].compute_delta_t()

    def get_summaries(self, key_list, first_only):
        # compose the headers
        headers = [ \
            'q_cc', \
            'q_AS', \
            'uids',
            'q_uid_tags',
            'q_repeats',
            'isp',
            'public',
            'both',
            'others',
           ]
        for tag in tag_list:
            headers.append(tag)
        s_list = []
        for key in key_list:
            if key in self.cc_AS_list:
                s_list.append(self.cc_AS_list[key].get_summary(first_only))
        s_list.sort(key=lambda x: x[2], reverse=True)
        df = pd.DataFrame(s_list, columns=headers)
        return df

    def get_delta_t_both(self, key):
        return self.cc_AS_list[key].get_delta_t_both()

    def get_subnets(self):
        sn = []
        for key in self.cc_AS_list:
            sn += self.cc_AS_list[key].get_subnets()
        sn_df = pd.DataFrame(sn, columns=subnet_record.headers())
        return sn_df

def do_graph(key, dot_df, image_file="", x_delay=False, log_y=False):
    if log_y:
        # replace 0 by low value so logy plots will work
        # also ensure that the low value of 1 microsec is at bottom of graph
        dot_df.loc[dot_df['delay'] < 0.000001, 'delay'] = 0.000001
    is_first = True
    sub_df = []
    x_value = "rank"
    if x_delay:
        x_value = "first_time"

    for rsv in tag_list:
        sub_df.append(dot_df[dot_df['rsv_type'] == rsv])

    legend_list = []
    for i in range(0, len(tag_list)):
        rsv = tag_list[i]
        rsv_color = color_list[i]
        if len(sub_df[i]) > 0:
            if is_first:
                axa = sub_df[i].plot.scatter(x=x_value, y="delay", logy=log_y, alpha=0.5, color=rsv_color)
            else:
                sub_df[i].plot.scatter(ax=axa, x=x_value, y="delay", logy=log_y, alpha=0.5, color=rsv_color)
            is_first = False
            legend_list.append(rsv)
    plt.title("Delay of second packets per query for " + key[:2] + "/" + key[2:])
    plt.legend(legend_list, loc='upper right')
    if len(image_file) == 0:
        plt.show()
    else:
        plt.savefig(image_file)
    plt.close()

    
def do_hist(key, dot_df, image_file):
    # get a frame from the list
    dot_df.loc[dot_df['delay'] == 0, 'delay'] += 0.000001
    is_first = True
    clrs = []
    legend_list = []
    row_list = []
    x_min = 1000000
    x_max = 0.000001

    for i in range(0, len(tag_list)):
        rsv = tag_list[i]
        sdf_all = dot_df[dot_df['rsv_type'] == rsv]
        sdf = sdf_all['delay']
        sdf_max = sdf.max()
        if sdf_max > x_max:
            x_max = sdf_max
        sdf_min = sdf.min()
        if sdf_min < x_min:
            x_min = sdf_min
        l = sdf.values.tolist()
        if len(l) > 0:
            row_list.append(np.array(l))
            clrs.append(color_list[i])
            legend_list.append(rsv)
            is_first = False
    if x_min < 0.000001:
        x_min = 0.000001

    if not is_first:
        logbins = np.logspace(np.log10(x_min),np.log10(x_max), num=20)
        axa = plt.hist(row_list, logbins, histtype='bar', color=clrs)
        plt.title("Histogram of delays to second packets per query for " + key[:2] + "/" + key[2:])
        plt.legend(legend_list, loc='upper right')
        plt.xscale('log')
        if len(image_file) == 0:
            plt.show()
        else:
            plt.savefig(image_file)
        plt.close()








