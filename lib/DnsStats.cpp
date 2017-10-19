/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <algorithm>
#include <vector>
#include "pcap_reader.h"
#include "DnsTypes.h"
#include "DnsStats.h"



DnsStats::DnsStats()
    :
    record_count(0),
    query_count(0),
    response_count(0),
    dnsstat_flags(0),
    max_query_usage_count(0x8000),
    max_tld_leakage_count(0x80),
    max_tld_leakage_table_count(0x8000)
{
}


DnsStats::~DnsStats()
{
}

static char const * DefaultRootAddresses[] = {
    "2001:503:ba3e::2:30",
    "198.41.0.4",
    "2001:500:200::b",
    "192.228.79.201",
    "2001:500:2::c",
    "192.33.4.12",
    "2001:500:2d::d",
    "199.7.91.13",
    "2001:500:a8::e",
    "192.203.230.10",
    "2001:500:2f::f",
    "192.5.5.241",
    "2001:500:12::d0d",
    "192.112.36.4",
    "2001:500:1::53",
    "198.97.190.53",
    "2001:7fe::53",
    "192.36.148.17",
    "2001:503:c27::2:30",
    "192.58.128.30",
    "2001:7fd::1",
    "193.0.14.129",
    "2001:500:9f::42",
    "199.7.83.42",
    "2001:dc3::35",
    "202.12.27.33"
};

static char const * RegistryNameById[] = {
    "0",
    "CLASS",
    "RR Type",
    "OpCode",
    "RCODE",
    "AFSDB RRSubtype",
    "DHCID RRIdType",
    "Label Type",
    "EDNS OPT CODE",
    "Header Flags",
    "EDNS Header_Flags",
    "EDNS Version number",
    "CSYNC Flags",
    "DNSSEC Algorithm Numbers",
    "DNSSEC KEY Prime Lengths",
    "Q-CLASS",
    "Q-RR Type",
    "DNSSEC Well Known Primes",
    "EDNS Packet Size",
    "Query Size",
    "Response Size",
    "TC Length",
    "Z-Q-TLD",
    "Z-R-TLD",
    "Z-Error Flags",
    "TLD Error Class",
    "Underlined part",
    "root-QR",
    "LeakByLength",
    "LeakedTLD",
    "RFC6761-TLD",
    "UsefulQueries",
    "DANE_CertUsage",
    "DANE_TlsaSelector",
    "DANE_TlsaMatchingType"
};

static uint32_t RegistryNameByIdNb = sizeof(RegistryNameById) / sizeof(char const*);

int DnsStats::SubmitQuery(uint8_t * packet, uint32_t length, uint32_t start, bool is_response)
{
    int rrclass = 0;
    int rrtype = 0;
    uint32_t name_start = start;

    start = SubmitName(packet, length, start, false);

    if (start + 4 <= length)
    {
        rrtype = (packet[start] << 8) | packet[start + 1];
        rrclass = (packet[start + 2] << 8) | packet[start + 3];
        start += 4;

        if (dnsstat_flags&dnsStateFlagCountQueryParms)
        {
            SubmitRegistryNumber(REGISTRY_DNS_Q_CLASSES, rrclass);
            SubmitRegistryNumber(REGISTRY_DNS_Q_RRType, rrtype);
        }

        if (dnsstat_flags&dnsStateFlagCountUnderlinedNames)
        {
            if (rrtype == DnsRtype_TXT)
            {
                SubmitRegistryString(REGISTRY_DNS_txt_underline, 3, (uint8_t *) "TXT");
                CheckForUnderline(packet, length, name_start);
            }
        }
    }
    else
    {
        error_flags |= DNS_REGISTRY_ERROR_FORMAT;
        start = length;
    }

    return start;
}

int DnsStats::SubmitRecord(uint8_t * packet, uint32_t length, uint32_t start, 
    uint32_t * e_rcode, uint32_t * e_length, bool is_response)
{
    int rrtype = 0;
    int rrclass = 0;
    unsigned int ttl = 0;
    int ldata = 0;
    int name_start = start;

    record_count++;

    /* Labels are only tabulated in responses, to avoid polluting data with erroneous packets */
    start = SubmitName(packet, length, start, is_response);

    if ((start + 10) > length)
    {
        error_flags |= DNS_REGISTRY_ERROR_FORMAT;
        start = length;
    }
    else
    {
        rrtype = (packet[start] << 8) | packet[start + 1];
        rrclass = (packet[start + 2] << 8) | packet[start + 3];
        ttl = (packet[start + 4] << 24) | (packet[start + 5] << 16)
            | (packet[start + 6] << 8) | packet[start + 7];
        ldata = (packet[start + 8] << 8) | packet[start + 9];

        if (start + ldata + 10 > length)
        {
            error_flags |= DNS_REGISTRY_ERROR_FORMAT;
            start = length;
        }
        else
        {
            if (ldata > 0 || rrtype == DnsRtype_OPT)
            {
                /* only record rrtypes and rrclass if valid response */
                if (rrtype != DnsRtype_OPT)
                {
                    if (is_response)
                    {
                        SubmitRegistryNumber(REGISTRY_DNS_CLASSES, rrclass);
                    }
                    else if (dnsstat_flags&dnsStateFlagCountQueryParms)
                    {
                        SubmitRegistryNumber(REGISTRY_DNS_Q_CLASSES, rrclass);
                    }
                }
                else
                {
                    /* document the extended length */
                    if (e_length != NULL)
                    {
                        *e_length = rrclass;
                    }
                }

                if (is_response)
                {
                    SubmitRegistryNumber(REGISTRY_DNS_RRType, rrtype);
                }
                else if (dnsstat_flags&dnsStateFlagCountQueryParms)
                {
                    SubmitRegistryNumber(REGISTRY_DNS_Q_RRType, rrtype);
                }

                /* Further parsing for OPT, DNSKEY, RRSIG, DS,
                 * and maybe also AFSDB, NSEC3, DHCID, RSYNC types */
                switch (rrtype)
                {
                case (int)DnsRtype_OPT:
                    SubmitOPTRecord(ttl, &packet[start + 10], ldata, e_rcode);
                    break;
                case (int)DnsRtype_DNSKEY:
                    SubmitKeyRecord(&packet[start + 10], ldata);
                    break;
                case (int)DnsRtype_RRSIG:
                    SubmitRRSIGRecord(&packet[start + 10], ldata);
                    break;
                case (int)DnsRtype_DS:
                    SubmitDSRecord(&packet[start + 10], ldata);
                    break;
                case (int)DnsRtype_TLSA:
                    SubmitTLSARecord(&packet[start + 10], ldata);
                    break;
                default:
                    break;
                }
            }

            start += ldata + 10;
        }
    }

    return start;
}

int DnsStats::SubmitName(uint8_t * packet, uint32_t length, uint32_t start, bool should_tabulate)
{
    uint32_t l = 0;
    uint32_t offset = 0;
    uint32_t name_start = start;

    while (start < length)
    {
        l = packet[start];

        if (l == 0)
        {
            /* end of parsing*/
            if (should_tabulate)
            {
                SubmitRegistryNumber(REGISTRY_DNS_LabelType, 0);
            }
            start++;
            break;
        }
        else if ((l & 0xC0) == 0xC0)
        {
            /* Name compression */
            if (should_tabulate)
            {
                SubmitRegistryNumber(REGISTRY_DNS_LabelType, 0xC0);
            }

            if ((start + 2) > length)
            {
                error_flags |= DNS_REGISTRY_ERROR_FORMAT;
                start = length;
                break;
            }
            else
            {
                start += 2;
                break;
            }
        }
        else if (l > 0x3F)
        {
            /* found an extension. Don't know how to parse it! */
            error_flags |= DNS_REGISTRY_ERROR_LABEL;
            if (should_tabulate)
            {
                SubmitRegistryNumber(REGISTRY_DNS_LabelType, l);
            }
            start = length;
            break;
        }
        else
        {
            /* regular name part. To do: tracking of underscore labels. */
            if (should_tabulate)
            {
                SubmitRegistryNumber(REGISTRY_DNS_LabelType, 0);
            }
            if (start + l + 1 > length)
            {
                error_flags |= DNS_REGISTRY_ERROR_FORMAT;
                start = length;
                break;
            }
            else
            {
                start += l + 1;
            }
        }
    }

    return start;
}

void DnsStats::SubmitOPTRecord(uint32_t flags, uint8_t * content, uint32_t length, uint32_t * e_rcode)
{
    uint32_t current_index = 0;

    /* Process the flags and rcodes */
    if (e_rcode != NULL)
    {
        *e_rcode = (flags >> 24) & 0xFF;
    }

    for (int i = 0; i < 16; i++)
    {
        if ((flags & (1 << i)) != 0)
        {
            SubmitRegistryNumber(REGISTRY_EDNS_Header_Flags, 15 - i);
        }
    }

    SubmitRegistryNumber(REGISTRY_EDNS_Version_number, (flags >> 16) & 0xFF);

    /* Find the options in the payload */
    while (current_index + 4 <= length)
    {
        uint32_t o_code = (content[current_index] << 8) | content[current_index + 1];
        uint32_t o_length = (content[current_index+2] << 8) | content[current_index + 3];
        current_index += 4 + o_length;
        SubmitRegistryNumber(REGISTRY_EDNS_OPT_CODE, o_code);
    }
}

void DnsStats::SubmitKeyRecord(uint8_t * content, uint32_t length)
{
    if (length > 8)
    {
        uint32_t algorithm = content[3];
        SubmitRegistryNumber(REGISTRY_DNSSEC_Algorithm_Numbers, algorithm);

        if (algorithm == 2)
        {
            uint32_t prime_length = (content[4] << 8) | content[5];
            if (prime_length < 16)
            {
                SubmitRegistryNumber(REGISTRY_DNSSEC_KEY_Prime_Lengths, prime_length);

                if (prime_length == 1 || prime_length == 2)
                {
                    uint32_t well_known_prime = (content[6] << 8) | content[7];
                    SubmitRegistryNumber(REGISTRY_DNSSEC_KEY_Well_Known_Primes, well_known_prime);
                }
            }
        }
    }
}

void DnsStats::SubmitRRSIGRecord(uint8_t * content, uint32_t length)
{
    if (length > 18)
    {
        uint32_t algorithm = content[2];
        SubmitRegistryNumber(REGISTRY_DNSSEC_Algorithm_Numbers, algorithm);
    }
}

void DnsStats::SubmitDSRecord(uint8_t * content, uint32_t length)
{
    if (length > 4)
    {
        uint32_t algorithm = content[2];
        SubmitRegistryNumber(REGISTRY_DNSSEC_Algorithm_Numbers, algorithm);
    }
}

void DnsStats::SubmitTLSARecord(uint8_t * content, uint32_t length)
{
    if (length >= 3)
    {
        SubmitRegistryNumber(REGISTRY_DANE_CertUsage, content[0]);
        SubmitRegistryNumber(REGISTRY_DANE_TlsaSelector, content[1]);
        SubmitRegistryNumber(REGISTRY_DANE_TlsaMatchingType, content[2]);
    }
}

void DnsStats::SubmitRegistryNumberAndCount(uint32_t registry_id, uint32_t number, uint32_t count)
{
    dns_registry_entry_t key;

    key.count = count;
    key.registry_id = registry_id;
    key.key_length = sizeof(uint32_t);
    key.key_type = 0; /* number */
    key.key_number = number;

    (void)hashTable.InsertOrAdd(&key);
}

void DnsStats::SubmitRegistryNumber(uint32_t registry_id, uint32_t number)
{
    SubmitRegistryNumberAndCount(registry_id, number, 1);
}

void DnsStats::SubmitRegistryStringAndCount(uint32_t registry_id, uint32_t length, uint8_t * value, uint32_t count)
{
    dns_registry_entry_t key;

    if (length < 64)
    {
        key.count = count;
        key.registry_id = registry_id;
        key.key_length = length;
        key.key_type = 1; /* string */
        memcpy(key.key_value, value, length);
        key.key_value[length] = 0;

        (void)hashTable.InsertOrAdd(&key);
    }
}

void DnsStats::SubmitRegistryString(uint32_t registry_id, uint32_t length, uint8_t * value)
{
    SubmitRegistryStringAndCount(registry_id, length, value, 1);
}

int DnsStats::CheckForUnderline(uint8_t * packet, uint32_t length, uint32_t start)
{
    uint32_t l = 0;
    uint32_t offset = 0;
    uint32_t previous = 0;
    uint32_t name_start = start;

    while (start < length)
    {
        l = packet[start];

        if (l == 0)
        {
            /* end of parsing*/
            start++;
            break;
        }
        else if ((l & 0xC0) == 0xC0)
        {
            if ((start + 2) > length)
            {
                /* error */
                start = length;
                break;
            }
            else
            {
                uint32_t new_start = ((l & 63) << 8) + packet[start + 1];

                if (new_start < name_start)
                {
                    (void)CheckForUnderline(packet, length, new_start);
                }

                start += 2;
                break;
            }
        }
        else if (l > 0x3F)
        {
            /* found an extension. Don't know how to parse it! */
            start = length;
            break;
        }
        else
        {
            /* Tracking of underscore labels. */
            if (start + l + 1 > length)
            {
                /* format error */
                start = length;
                break;
            }
            else
            {
                if (l > 0 && packet[start + 1] == '_')
                {
                    uint8_t underlined_name[64];
                    uint32_t flags;

                    NormalizeNamePart(l, &packet[start + 1], underlined_name, &flags);

                    if ((flags & 3) == 0)
                    {
                        SubmitRegistryString(REGISTRY_DNS_txt_underline, l, underlined_name);
                    }
                }
                previous = start;
                start += l + 1;
            }
        }
    }

    return start;
}

int DnsStats::GetTLD(uint8_t * packet, uint32_t length, uint32_t start, uint32_t * offset)
{
    int ret = 0;
    uint32_t l = 0;
    uint32_t previous = 0;
    uint32_t name_start = start;

    while (start < length)
    {
        l = packet[start];

        if (l == 0)
        {
            /* end of parsing*/

            if (previous != 0)
            {
                *offset = previous;
            }
            else
            {
                ret = -1;
            }
            break;
        }
        else if ((l & 0xC0) == 0xC0)
        {
            /* Name compression */
            if ((start + 2) > length)
            {
                ret = -1;
                break;
            }
            else
            {
                uint32_t new_start = ((l & 63) << 8) + packet[start + 1];
                
                if (new_start < name_start)
                {
                    ret = GetTLD(packet, length, new_start, offset);
                }
                else
                {
                    ret = -1;
                }
                break;
            }
        }
        else if (l > 0x3F)
        {
            /* Unexpected name part */
            ret = -1;
            break;
        }
        else
        {
            if (start + l + 1 > length)
            {
                /* malformed name part */
                ret = -1;
                break;
            }
            else
            {
                previous = start;
                start += l + 1;
            }
        }
    }

    return start;
}

void DnsStats::NormalizeNamePart(uint32_t length, uint8_t * value,
    uint8_t * normalized, uint32_t * flags)
{
    bool has_letter = false;
    bool has_number = false;
    bool has_special = false;
    bool has_dash = false;
    bool has_non_ascii = false;

    for (uint32_t i = 0; i < length; i++)
    {
        uint8_t c = value[i];
        if (c >= 'A' && c <= 'Z')
        {
            has_letter = true;
        }
        else if (c >= 'a' && c <= 'z')
        {
            has_letter = true;
        }
        else if (c >= '0' && c <= '9')
        {
            has_number = true;
        }
        else if (c == '-' || c == '_')
        {
            has_dash = true;
        }
        else if (c > 127)
        {
            has_non_ascii = true;
        }
        else if (c <= ' ' || c == 127 || c == '"' || c == ',')
        {
            c = '?';
            has_special = true;
        }
        else
        {
            has_special = true;
        }
        normalized[i] = c;
    }
    normalized[length] = 0;

    if (flags != NULL)
    {
        *flags = 0;

        if (has_non_ascii)
        {
            *flags += 1;
        }
        else if (has_special)
        {
            *flags += 2;
        }

        if (has_letter)
        {
            *flags += 64;
        }
        if (has_number)
        {
            *flags += 128;
        }
        if (has_dash)
        {
            *flags += 256;
        }
    }
}

void DnsStats::GetSourceAddress(int ip_type, uint8_t * ip_header, uint8_t ** addr, size_t * addr_length)
{
    if (ip_type == 4)
    {
        *addr = ip_header + 12;
        *addr_length = 4;
    }
    else
    {
        *addr = ip_header + 8;
        *addr_length = 16;
    }
}

void DnsStats::GetDestAddress(int ip_type, uint8_t * ip_header, uint8_t ** addr, size_t * addr_length)
{
    if (ip_type == 4)
    {
        *addr = ip_header + 16;
        *addr_length = 4;
    }
    else
    {
        *addr = ip_header + 24;
        *addr_length = 16;
    }
}

bool CompareTldEntries(TldAsKey * x, TldAsKey * y)
{
    bool ret = x->count >  y->count;

    if (x->count == y->count)
    {
        for (size_t i = 0; i < x->tld_len; i++)
        {
            if (x->tld[i] != x->tld[i])
            {
                ret = x->tld[i] < x->tld[i];
                break;
            }
        }
    }

    return ret;
}


bool DnsStats::IsNumericDomain(uint8_t * tld, uint32_t length)
{
    bool ret = true;

    for (uint32_t i = 0; i < length; i++)
    {
        if (tld[i] < '0' || tld[i] > '9')
        {
            ret = false;
            break;
        }
    }

    return ret;
}

void DnsStats::ExportLeakedDomains()
{
    TldAsKey *tld_entry;
    std::vector<TldAsKey *> lines(tldLeakage.GetCount());
    int vector_index = 0;
    uint32_t export_count = 0;

    for (uint32_t i = 0; i < tldLeakage.GetSize(); i++)
    {
        tld_entry = tldLeakage.GetEntry(i);

        while (tld_entry != NULL)
        {
            lines[vector_index] = tld_entry;
            vector_index++;
            tld_entry = tld_entry->HashNext;
        }
    }

    std::sort(lines.begin(), lines.end(), CompareTldEntries);

    /* Retain the N most interesting values */
    for (TldAsKey * &entry : lines)
    {
        if (export_count < max_tld_leakage_count &&
            !IsNumericDomain(entry->tld, entry->tld_len))
        {
            SubmitRegistryStringAndCount(REGISTRY_DNS_LeakedTLD, 
                entry->tld_len, entry->tld, entry->count);
            export_count++;
        }
    }
}

static char const * rfc6761_tld[] = {
    "EXAMPLE",
    "INVALID",
    "LOCAL",
    "LOCALHOST",
    "ONION",
    "TEST"
};

const uint32_t nb_rfc6771_tld = sizeof(rfc6761_tld) / sizeof(char const *);

bool DnsStats::IsRfc6761Tld(uint8_t * tld, size_t length)
{
    bool ret = false;

    for (uint32_t i = 0; i < nb_rfc6771_tld; i++)
    {
        size_t j = 0;
        uint8_t * x = (uint8_t *)rfc6761_tld[i];

        for (; j < length; j++)
        {
            if (x[j] != tld[j] && (x[j] - 'A' + 'a') != tld[j])
            {
                break;
            }
        }

        if (j == length && x[j] == 0)
        {
            ret = true;
            break;
        }
    }
    return ret;
}

void DnsStats::SetToUpperCase(uint8_t * domain, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        int c = domain[i];

        if (c >= 'a' && c <= 'z')
        {
            c += 'A' - 'a';
            domain[i] = (uint8_t)c;
        }
    }
}

char const * DnsStats::GetTableName(uint32_t tableId)
{
    char const * ret = NULL;

    if (tableId < RegistryNameByIdNb)
    {
        ret = RegistryNameById[tableId];
    }

    return ret;
}

/*
* Examine the packet level information
*
* - DNS OpCodes
* - DNS RCodes
* - DNS Header Flags
*
* Analyze queries and responses.
* Special cases for TXT, KEY, CSYNC
*

1  1  1  1  1  1
0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

bool DnsStats::LoadPcapFiles(size_t nb_files, char const ** fileNames)
{
    bool ret = true;

    for (size_t i = 0; ret && i < nb_files; i++)
    {
        ret = LoadPcapFile(fileNames[i]);
    }

    return ret;
}

bool DnsStats::LoadPcapFile(char const * fileName)
{
    bool ret = true;
    pcap_reader reader;
    size_t nb_records_read = 0;
    size_t nb_udp_dns_frag = 0;
    size_t nb_udp_dns = 0;

    if (!reader.Open(fileName, NULL))
    {
        ret = false;
    }
    else
    {
        while (reader.ReadNext())
        {
            nb_records_read++;

            if (reader.tp_version == 17 &&
                (reader.tp_port1 == 53 || reader.tp_port2 == 53))
            {
                if (reader.is_fragment)
                {
                    nb_udp_dns_frag++;
                }
                else
                {
                    SubmitPacket(reader.buffer + reader.tp_offset + 8,
                        reader.tp_length - 8, reader.ip_version, reader.buffer + reader.ip_offset);
                    nb_udp_dns++;
                }
            }
        }
    }

    return ret;
}

void DnsStats::SubmitPacket(uint8_t * packet, uint32_t length, int ip_type, uint8_t* ip_header)
{
    bool is_response;
    uint8_t * source_addr;
    size_t source_addr_length;
    uint8_t * dest_addr;
    size_t dest_addr_length;

    bool has_header = true;
    uint32_t flags = 0;
    uint32_t opcode = 0;
    uint32_t rcode = 0;
    uint32_t e_rcode = 0;
    uint32_t qdcount = 0;
    uint32_t ancount = 0;
    uint32_t nscount = 0;
    uint32_t arcount = 0;
    uint32_t parse_index = 0;
    uint32_t e_length = 512;
    uint32_t tc_bit = 0;

    error_flags = 0;

    if (rootAddresses.GetCount() == 0)
    {
        rootAddresses.SetList(DefaultRootAddresses, sizeof(DefaultRootAddresses) / sizeof(char const *));
    }

    if (length < 12)
    {
        error_flags |= DNS_REGISTRY_ERROR_FORMAT;
        parse_index = length;
        has_header = false;
    }
    else
    {
        is_response = ((packet[2] & 128) != 0);
        GetSourceAddress(ip_type, ip_header, &source_addr, &source_addr_length);
        GetDestAddress(ip_type, ip_header, &dest_addr, &dest_addr_length);


        if (is_response)
        {
            response_count++;
        }
        else
        {
            query_count++;
        }

        flags = ((packet[2] & 7) << 4) | ((packet[3] & 15) >> 4);
        opcode = (packet[2] >> 3) & 15;
        rcode = (packet[3] & 15);
        qdcount = (packet[4] << 8) | packet[5];
        ancount = (packet[6] << 8) | packet[7];
        nscount = (packet[8] << 8) | packet[9];
        arcount = (packet[10] << 8) | packet[11];

        SubmitRegistryNumber(REGISTRY_DNS_OpCodes, opcode);

        if (is_response && opcode == DNS_OPCODE_QUERY 
            && rootAddresses.IsInList(source_addr, source_addr_length))
        {
            uint32_t tld_offset = 0;
            int gotTld = GetTLD(packet, length, 12, &tld_offset);

            if (gotTld)
            {
                SetToUpperCase(packet + tld_offset + 1, packet[tld_offset]);
            }
            
            SubmitRegistryNumber(REGISTRY_DNS_root_QR, rcode);

            if (gotTld)
            {
                if (rcode == DNS_RCODE_NXDOMAIN)
                {
                    /* Analysis of domain leakage */
                    if (IsRfc6761Tld(packet + tld_offset + 1, packet[tld_offset]))
                    {
                        SubmitRegistryString(REGISTRY_DNS_RFC6761TLD, packet[tld_offset], packet + tld_offset + 1);
                    }
                    else
                    {
                        /* Insert in leakage table */
                        TldAsKey key(packet + tld_offset + 1, packet[tld_offset]);
                        bool stored = false;
                        (void)tldLeakage.InsertOrAdd(&key, true, &stored);

                        /* TODO: If full enough, remove the LRU */
                        if (tldLeakage.GetCount() > max_tld_leakage_table_count)
                        {
                            TldAsKey * removed = tldLeakage.RemoveLRU();
                            if (removed != NULL)
                            {
                                delete removed;
                            }
                        }
                        /* Add count of leaks by length, including all packets */
                        SubmitRegistryNumber(REGISTRY_DNS_LeakByLength, packet[tld_offset]);
                    }
                }
                else if (rcode == DNS_RCODE_NOERROR)
                {
                    /* Analysis of useless traffic to the root */
                    TldAddressAsKey key(dest_addr, dest_addr_length, packet + tld_offset + 1, packet[tld_offset]);

                    if (queryUsage.GetCount() >= max_query_usage_count)
                    {
                        /* Table is full. Just keep counting the transactions that are present */
                        TldAddressAsKey * present = queryUsage.Retrieve(&key);
                        if (present != NULL)
                        {
                            present->count++;
                            SubmitRegistryNumber(REGISTRY_DNS_UsefulQueries, 0);
                        }
                    }
                    else
                    {
                        bool stored = false;
                        (void)queryUsage.InsertOrAdd(&key, true, &stored);

                        SubmitRegistryNumber(REGISTRY_DNS_UsefulQueries, (stored)?1:0);
                    }

                    if (dnsstat_flags&dnsStateFlagCountTld)
                    {
                        SubmitRegistryString(REGISTRY_TLD_response, packet[tld_offset], packet + tld_offset + 1);
                    }
                }
            }
        }

        for (uint32_t i = 0; i < 7; i++)
        {
            if ((flags & (1 << i)) != 0)
            {
                SubmitRegistryNumber(REGISTRY_DNS_Header_Flags, i);
            }
        }

        parse_index = 12;
    }

    for (uint32_t i = 0; i < qdcount; i++)
    {
        if (parse_index >= length)
        {
            error_flags |= DNS_REGISTRY_ERROR_FORMAT;
        }
        else
        {
            parse_index = SubmitQuery(packet, length, parse_index, is_response);
        }
    }

    for (uint32_t i = 0; i < ancount; i++)
    {
        if (parse_index >= length)
        {
            error_flags |= DNS_REGISTRY_ERROR_FORMAT;
        }
        else
        {
            parse_index = SubmitRecord(packet, length, parse_index, NULL, NULL, is_response);
        }
    }

    for (uint32_t i = 0; i < nscount; i++)
    {
        if (parse_index >= length)
        {
            error_flags |= DNS_REGISTRY_ERROR_FORMAT;
        }
        else
        {
            parse_index = SubmitRecord(packet, length, parse_index, NULL, NULL, is_response);
        }
    }

    for (uint32_t i = 0; i < arcount; i++)
    {
        if (parse_index >= length)
        {
            error_flags |= DNS_REGISTRY_ERROR_FORMAT;
        }
        else
        {
            parse_index = SubmitRecord(packet, length, parse_index, &e_rcode, &e_length, is_response);
        }
    }

    if (has_header)
    {
        rcode |= (e_rcode << 4);
        SubmitRegistryNumber(REGISTRY_DNS_RCODES, rcode);
    }

    if (has_header && (dnsstat_flags&dnsStateFlagCountPacketSizes) != 0)
    {
        if (is_response)
        {
            SubmitRegistryNumber(REGISTRY_DNS_Response_Size, length);
            if ((flags & (1 << 5)) != 0)
            {
                SubmitRegistryNumber(REGISTRY_DNS_TC_length, e_length);
            }
        }
        else
        {
            SubmitRegistryNumber(REGISTRY_DNS_Query_Size, length);
            SubmitRegistryNumber(REGISTRY_EDNS_Packet_Size, e_length);
        }
    }

    SubmitRegistryNumber(REGISTRY_DNS_error_flag, error_flags);
}

bool CompareRegistryEntries(dns_registry_entry_t * x, dns_registry_entry_t * y)
{
    bool ret = false;

    if (x->registry_id < y->registry_id)
    {
        ret = true;
    }
    else if (x->registry_id == y->registry_id)
    {
        if (x->key_type < y->key_type)
        {
            ret = true;
        }
        else if (x->key_type == y->key_type)
        {
            if (x->key_type == 0)
            {
                ret = (x->key_number < y->key_number);
            }
            else
            {
                for (int i = 0; i < sizeof(x->key_value); i++)
                {
                    if (x->key_value[i] < y->key_value[i])
                    {
                        ret = true;
                        break;
                    }
                    else if (x->key_value[i] != y->key_value[i])
                    {
                        break;
                    }
                }
            }
        }
    }

    return ret;
}

bool DnsStats::ExportToCaptureSummary(CaptureSummary * cs)
{
    dns_registry_entry_t *entry;
    bool ret = true;

    if (ret)
    {
        /* Get the ordered list of leaked domain into the main hash */
        ExportLeakedDomains();
    }

    if (ret)
    {
        cs->Reserve(hashTable.GetSize());

        for (uint32_t i = 0; i < hashTable.GetSize(); i++)
        {
            entry = hashTable.GetEntry(i);
            if (entry != NULL)
            {
                CaptureLine line;

                if (entry->registry_id < RegistryNameByIdNb)
                {
                    memcpy(line.registry_name, RegistryNameById[entry->registry_id],
                        strlen(RegistryNameById[entry->registry_id]) + 1);
                }
                else
                {
#ifdef _WINDOWS
                    if (_itoa_s(entry->registry_id, line.registry_name,
                        sizeof(line.registry_name), 10) != 0)
                    {
                        ret = false;
                    }
#else
                    (void)itoa(entry->registry_id, line.registry_name, 10);
#endif
                }
                line.key_type = entry->key_type;

                if (entry->key_type == 0)
                {
                    line.key_number = entry->key_number;
                }
                else
                {
                    /* Check that the value is printable */
                    bool printable = true;
                    for (uint32_t i = 0; i < entry->key_length; i++)
                    {
                        int x = entry->key_value[i];

                        if (x >= ' ' && x < 127 && x != '"' && x != ',')
                        {
                            continue;
                        }
                        else
                        {
                            printable = false;
                            break;
                        }
                    }
                    if (!printable)
                    {
                        size_t byte_index = 3;
                        line.key_value[0] = '_';
                        line.key_value[1] = '0';
                        line.key_value[2] = 'x';
                        for (uint32_t i = 0; i < entry->key_length; i++)
                        {
                            if (byte_index + 3 < sizeof(line.key_value))
                            {
                                uint8_t x[2];
                                x[0] = entry->key_value[i] >> 4;
                                x[1] = entry->key_value[i] & 0x0F;

                                for (int j = 0; j < 2; j++)
                                {
                                    int c = (x[j] < 10) ? '0' + x[j] : 'a' + x[j] - 10;
                                    line.key_value[byte_index++] = c;
                                }
                            }
                        }
                        line.key_value[byte_index] = 0;
                    }
                    else
                    {
                        memcpy(line.key_value, entry->key_value, entry->key_length);
                        line.key_value[entry->key_length] = 0;
                    }
                }
                line.count = entry->count;

                cs->AddLine(&line, true);
            }
        }

        cs->Sort();
    }

    return ret;
}

TldAsKey::TldAsKey(uint8_t * tld, size_t tld_len)
    :
    HashNext(NULL),
    MoreRecentKey(NULL),
    LessRecentKey(NULL),
    count(1),
    hash(0)
{
    CanonicCopy(this->tld, sizeof(this->tld) - 1, &this->tld_len, tld, tld_len);
}

TldAsKey::~TldAsKey()
{
}

bool TldAsKey::IsSameKey(TldAsKey * key)
{
    bool ret = (this->tld_len == key->tld_len &&
        memcmp(this->tld, key->tld, this->tld_len) == 0);

    return ret;
}

uint32_t TldAsKey::Hash()
{
    if (hash == 0)
    {
        hash = 0xBABAC001;

        for (size_t i = 0; i < tld_len; i++)
        {
            hash = hash * 101 + tld[i];
        }
    }

    return hash;
}

TldAsKey * TldAsKey::CreateCopy()
{
    TldAsKey * ret = new TldAsKey(this->tld, this->tld_len);

    if (ret != NULL)
    {
        ret->count = count;
    }

    return ret;
}

void TldAsKey::Add(TldAsKey * key)
{
    this->count += key->count;
}

void TldAsKey::CanonicCopy(uint8_t * tldDest, size_t tldDestMax, size_t * tldDestLength, 
    uint8_t * tldSrce, size_t tldSrceLength)
{
    size_t i = 0;

    for (; i < tldSrceLength && i < tldDestMax; i++)
    {
        int c = tldSrce[i];

        if (c >= 'a' && c <= 'z')
        {
            c += 'A' - 'a';
        }

        tldDest[i] = c;
    }

    *tldDestLength = i;

    tldDest[i] = 0;
}


TldAddressAsKey::TldAddressAsKey(uint8_t * addr, size_t addr_len, uint8_t * tld, size_t tld_len)
    :
    HashNext(NULL),
    count(1),
    hash(0)
{
    if (addr_len > 16)
    {
        addr_len = 16;
    }

    memcpy(this->addr, addr, addr_len);
    this->addr_len = addr_len;

    TldAsKey::CanonicCopy(this->tld, sizeof(this->tld) - 1, &this->tld_len, tld, tld_len);
}

TldAddressAsKey::~TldAddressAsKey()
{
}

bool TldAddressAsKey::IsSameKey(TldAddressAsKey * key)
{
    bool ret = (this->tld_len == key->tld_len &&
        memcmp(this->tld, key->tld, this->tld_len) == 0 &&
        this->addr_len == key->addr_len &&
        memcmp(this->addr, key->addr, this->addr_len) == 0);

    return ret;
}

uint32_t TldAddressAsKey::Hash()
{
    if (hash == 0)
    {
        hash = 0xCACAB0B0;

        for (size_t i = 0; i < tld_len; i++)
        {
            hash = hash * 101 + tld[i];
        }

        for (size_t i = 0; i < addr_len; i++)
        {
            hash = hash * 101 + addr[i];
        }
    }

    return hash;
}

TldAddressAsKey * TldAddressAsKey::CreateCopy()
{
    TldAddressAsKey* ret = new TldAddressAsKey(addr, addr_len, tld, tld_len);

    if (ret != NULL)
    {
        ret->count = count;
    }

    return ret;
}

void TldAddressAsKey::Add(TldAddressAsKey * key)
{
    this->count += key->count;
}
