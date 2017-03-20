//
//  main.cpp
//  balancer
//
//  Created by Claudio Landeros on 3/4/16.
//  Copyright (c) 2016 Claudio Landeros. All rights reserved.
//

#include <iostream>
#include <unistd.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <sstream>
#include <fstream>
#include<signal.h>
#include<unistd.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 65535

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

struct UDP_hdr {
    u_short	uh_sport;		/* source port */
    u_short	uh_dport;		/* destination port */
    u_short	uh_ulen;		/* datagram length */
    u_short	uh_sum;			/* datagram checksum */
};


typedef std::pair<int, int>                    analyzer_value;
typedef std::pair<std::string, std::string>         analyzer_key;
typedef std::map<analyzer_key, analyzer_value>      analyzer_map;

typedef std::tuple<std::string, std::string, uint16_t, uint16_t, std::string>   balancer_key;
typedef std::pair<int, int>                                                     balancer_value;
typedef std::map<balancer_key, balancer_value>                                  balancer_map;

typedef int                                 packet_key;
typedef std::pair<int, int>                 packet_value;
typedef std::map<packet_key, balancer_value>  packet_map;

typedef int server_key;
typedef std::tuple<int, std::string, balancer_key, int> server_vector_value;
typedef std::vector<server_vector_value> server_value;
typedef std::map<server_key, server_value> server_map;

struct balancer_pointers{
    balancer_map* balancer_map_pointer;
    packet_map* packet_map_pointer;
    server_map* server_map_pointer;
    std::vector<int> *percentages_array_pointer;
};

using namespace std;

void analyzer_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void balancer_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void showhelpinfo(char *s);
int analyze(char*, char*, char*);
int balance(char*, char*, char*, vector<int>);
void print_analyze(analyzer_map, char*);
void print_balancer(balancer_map, packet_map, server_map, vector<int>, char*);

bool pflag = false;
bool bflag = false;
bool sflag = false;
bool dflag = false;
pcap_t *handle;

int main (int argc,char *argv[])
{
    
    char* rFile = NULL;
    char* interface = NULL;
    char* lFile = NULL;
    int numServers = 0;
    
    vector<int> serversArray;
    char* percentagesChar = NULL;
    
    char tmp;
    /*if the program is ran witout options ,it will show the usgage and exit*/
    if(argc == 1)
    {
        showhelpinfo(argv[0]);
        exit(1);
    }
    
    while((tmp=getopt(argc,argv,"pbsdr:i:l:w:c:"))!=-1)
    {
        switch(tmp)
        {
            case 'p':
                pflag = true;
                cout<<"p";
                break;
                
            case 'b':
                bflag = true;
                cout<<"b";
                break;
                
            case 's':
                sflag = true;
                cout<<"s";
                break;
                
            case 'd':
                dflag = true;
                cout<<"d";
                break;
                
            case 'r':
                rFile = optarg;
                cout<<rFile;
                break;
                
            case 'i':
                interface = optarg;
                cout<<interface;
                break;
                
            case 'l':
                lFile = optarg;
                cout<<lFile;
                break;
                
            case 'w':
                numServers = atoi(optarg);
                break;
                
            case 'c':
                percentagesChar = optarg;
                break;
                
            default:
                showhelpinfo(argv[0]);
                break;
        }
    }
    
    if((rFile != NULL && interface != NULL) || (rFile == NULL && interface == NULL)){
        showhelpinfo(argv[0]);
        return -1;
    }
    else if ((numServers != 0 || percentagesChar != NULL) && (sflag || pflag || bflag || dflag)){
        showhelpinfo(argv[0]);
        return -1;
    }
    else if(sflag || pflag || bflag || dflag){
        if (analyze(rFile, interface, lFile) == -1) {
            fprintf(stderr,"\nError analyzing\n");
        }
    }
    else if(numServers != 0 && percentagesChar != NULL){
        int i = 0;
        int w = 0;
        string p = "";
        int x = 0;
        
        while (percentagesChar[i] != '\0') {
            if (percentagesChar[i] == ':') {
                x = stoi(p);
                serversArray.push_back(x);
                w++;
                p = "";
            }
            else {
                p += percentagesChar[i];
            }
            i++;
        }
        x = stoi(p);
        serversArray.push_back(x);
        if (w != numServers-1) {
            showhelpinfo(argv[0]);
            return -1;
        }
        
        if(balance(rFile, interface, lFile, serversArray) == -1){
            fprintf(stderr,"\nError balancing\n");
            return -1;
        }
    }
    
    return 0;
}

/*funcion that show the help information*/
void showhelpinfo(char *s)
{
    cout<<"Usage:   "<<s<<" [-option] [argument]"<<endl;
    cout<<"option:  "<<"-r  Read the specified pcap file"<<endl;
    cout<<"         "<<"-i  Listen on the specified interface"<<endl;
    cout<<"         "<<"-l  Logfile with the summary report"<<endl;
    cout<<"         "<<"-p  Output packet counts"<<endl;
    cout<<"         "<<"-b  Output byte counts"<<endl;
    cout<<"         "<<"-s  Analyze based on source IP"<<endl;
    cout<<"         "<<"-d  Analyze based on destination IP"<<endl;
}

void terminate_process(int signum)
{
    pcap_breakloop(handle);
}

pcap_t* initializeHandle(char* rFile, char* interface, struct bpf_program fp){
    
    /* most code here taken from sniffex.c*/
    
    char *dev = interface;			/* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    //pcap_t *handle;				/* packet capture handle */
    char filter_exp[] = "ip";		/* filter expression [3] */
    bpf_u_int32 mask;               /* subnet mask */
    bpf_u_int32 net = 0;			/* ip */
    
    if (dev == NULL) {
        
        if ((handle = pcap_open_offline_with_tstamp_precision(rFile, PCAP_TSTAMP_PRECISION_MICRO, errbuf)) == NULL)
        {
            fprintf(stderr,"\nError opening dump file\n");
            exit(EXIT_FAILURE);
        }
    }
    else if (rFile == NULL){
        
        /* get network number and mask associated with capture device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                    dev, errbuf);
            net = 0;
            mask = 0;
        }
        
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }
    }
    else {
        fprintf(stderr, "File and Interface NULL");
        exit(EXIT_FAILURE);
    }
    
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }
    
    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    return handle;
}

int balance(char* rFile, char* interface, char* lFile, vector<int> serversArray){
    
    //pcap_t *handle;                 /* packet capture handle */
    struct bpf_program fp;			/* compiled filter program (expression) */
    
    balancer_pointers bp;
    balancer_map b_map;
    packet_map pack_map;
    server_map s_map;
    
    bp.balancer_map_pointer = &b_map;
    bp.packet_map_pointer = &pack_map;
    bp.server_map_pointer = &s_map;
    bp.percentages_array_pointer = &serversArray;
    
    u_char* bp_to_char;
    bp_to_char = (u_char*)&bp;
    
    handle = initializeHandle(rFile, interface, fp);
    if (handle == NULL) {
        fprintf(stderr, "Handle returned NULL");
        return -1;
    }
    
    srand(time(0));
    signal(SIGINT, terminate_process);
    /* now we can set our callback function */
    pcap_loop(handle, 0, balancer_callback, bp_to_char);
    
    /* cleanup */
    // pcap_freecode(&fp);
    pcap_close(handle);
    
    //print
    print_balancer(b_map, pack_map, s_map, serversArray, lFile);
    
    return 0;
}

void print_balancer(balancer_map b_map, packet_map p_map, server_map s_map, vector<int> serversArray, char* lFile){
    
    ofstream file;
    file.open(lFile, ios::out | ios::trunc);
    string message = "";
    server_vector_value s_value;
    balancer_key b_key;
    
    file << "pkt_id\tflow_id\tserver_id\n";
    for (packet_map::iterator it = p_map.begin(); it!=p_map.end(); it++) {
        file << it->first;
        file << "\t";
        file << it->second.first;
        file << "\t";
        file << it->second.second;
        file << "\n";
    }
    file.flush();
    file.close();
    
    for (int i = 0; i < serversArray.size(); i++) {
        message = "webserver.";
        message += to_string(i+1);
        file.open(message, ios::out | ios::trunc);
        file << "pkt_id\t\t\ttimestamp\t\t\tsrc_ip\t\t\tdst_ip\t\tsrc_port\tdst_port\tprotocol\tpkt_len\n";
        
        server_map::iterator it = s_map.find(i+1);
        if (it != s_map.end()) {
            for (server_value::iterator iter = it->second.begin(); iter!= it->second.end(); iter++) {
                s_value = *iter;
                file << "\t";
                file << get<0>(s_value);
                file << "\t\t";
                file << get<1>(s_value);
                file << "\t";
                
                b_key =  get<2>(s_value);
                file << get<0>(b_key);
                file << "\t";
                file << get<1>(b_key);
                file << "\t\t";
                file << get<2>(b_key);
                file << "\t\t";
                file << get<3>(b_key);
                file << "\t\t\t";
                file << get<4>(b_key);
                file << "\t\t\t";
                file << get<3>(s_value);
                file << "\n";
            }
        }
        file.flush();
        file.close();
    }
}

int analyze(char* rFile, char* interface, char* lFile){
    
    //pcap_t *handle;                 /* packet capture handle */
    struct bpf_program fp;			/* compiled filter program (expression) */
    
    analyzer_map map;
    u_char* map_to_char;
    map_to_char = (u_char*)&map;
    
    handle = initializeHandle(rFile, interface, fp);
    if (handle == NULL) {
        fprintf(stderr, "Handle returned NULL");
        return -1;
    }
    
    signal(SIGINT, terminate_process);
    /* now we can set our callback function */
    pcap_loop(handle, 0, analyzer_callback, map_to_char);
    
    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    
    //print
    print_analyze(map, lFile);
    
    return 0;
}

void print_analyze(analyzer_map a_map, char* lFile){
    
    map<string, analyzer_value> print_map;
    analyzer_key print_key;
    analyzer_value print_value;
    ofstream file;
    file.open(lFile, ios::out | ios::trunc);
    string message = "";
    stringstream ss;
    
    for (analyzer_map::iterator it = a_map.begin(); it!=a_map.end(); it++) {
        if (sflag && dflag) {
            print_value.first = it->second.first;
            print_value.second = it->second.second;
            
            if (print_map.find(it->first.first + "\t" + it->first.second) != print_map.end()) {
                print_map[it->first.first].first += print_value.first;
                print_map[it->first.first].second += print_value.second;
            }
            else {
                print_map[it->first.first + "\t" + it->first.second] = print_value;
            }
        }
        else if (sflag && !dflag) {
            print_value.first = it->second.first;
            print_value.second = it->second.second;
            
            if (print_map.find(it->first.first) != print_map.end()) {
                print_map[it->first.first].first += print_value.first;
                print_map[it->first.first].second += print_value.second;
            }
            else {
                print_map[it->first.first] = print_value;
            }
        }
        else if (dflag && !sflag){
            print_value.first = it->second.first;
            print_value.second = it->second.second;
            
            if (print_map.find(it->first.second) != print_map.end()) {
                print_map[it->first.second].first += print_value.first;
                print_map[it->first.second].second += print_value.second;
            }
            else {
                print_map[it->first.second] = print_value;
            }
        }
    }
    
    for (map<string, analyzer_value>::iterator it = print_map.begin(); it!=print_map.end(); it++) {
        
        message = it->first;
        message += "\t";
        file << message;
        
        if (pflag) {
            message = to_string(it->second.first);
            message += "\t";
            file << message;
        }
        if (bflag) {
            ss.str(std::string());
            ss << it->second.second;
            message = ss.str();
            file << message;
        }
        file << "\n";
    }
    file.close();
}

void analyzer_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    
    analyzer_map* map = (analyzer_map*)args;
    analyzer_key key;
    analyzer_value value;
    int packet_count =0;
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    
    int size_ip;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    
    key.first = strdup(inet_ntoa(ip->ip_src));
    key.second = strdup(inet_ntoa(ip->ip_dst));
    
    cout << key.first;
    cout << "\t";
    cout << key.second;
    cout << "\t";
    
    value = map->operator[](key);
    packet_count = value.first;
    packet_count++;
    value.first = packet_count;
    cout << value.first;
    cout << "\n";
    value.second += ntohs(ip->ip_len);
    map->operator[](key) = value;
    
    return;
}

void balancer_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    
    balancer_pointers* bp = (balancer_pointers*)args;
    balancer_map *b_map = bp->balancer_map_pointer;
    packet_map *p_map = bp->packet_map_pointer;
    server_map *s_map = bp->server_map_pointer;
    vector<int> *serversArray = bp->percentages_array_pointer;
    
    balancer_key b_key;
    balancer_value b_value;
    packet_key p_key;
    server_vector_value s_value;
    server_value serv_value;
    
    static int packet_count = 1;                   /* packet counter */
    static int flow_count = 0;                      /* flow counter */
    int flowIndex = 1;
    int serverIndex = 1;
    string protocol = "";
    uint16_t src_prt;
    uint16_t dst_prt;
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct UDP_hdr *udp;              /* The UDP header */
    
    int size_ip;
    int size_tcp;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    
    /*switch taken and some of above taken from sniffex.c */
    
    /* determine protocol */
    switch(ip->ip_p) {
            
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            /* define/compute tcp header offset */
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            src_prt = ntohs(tcp->th_sport);
            dst_prt = ntohs(tcp->th_dport);
            protocol = "tcp";
            break;
            
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            udp = (struct UDP_hdr*)(packet + SIZE_ETHERNET + size_ip);
            
            if (header->len - (size_ip + SIZE_ETHERNET) < sizeof(struct UDP_hdr))
            {
                printf("   * Invalid UDP header length\n");
                return;
            }
            src_prt = ntohs(udp->uh_sport);
            dst_prt = ntohs(udp->uh_dport);
            protocol = "udp";
            break;
            
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }
    
    get<0>(b_key) = strdup(inet_ntoa(ip->ip_src));
    get<1>(b_key) = strdup(inet_ntoa(ip->ip_dst));
    get<2>(b_key) = src_prt;
    get<3>(b_key) = dst_prt;
    get<4>(b_key) = protocol;
    
    balancer_map::iterator it = b_map->find(b_key);
    if (it != b_map->end()) {
        b_value = it->second;
        flowIndex = b_value.first;
        serverIndex = b_value.second;
        cout<< "existing flow\n";
    }
    else{
        cout<< "new flow\n";
        int val = rand() % 100;
        int prev = 0;
        /*int i = 0;
         while (val > serversArray->operator[](i) + prev) {
         serverIndex = i+1;
         flow_count++;
         flowIndex = flow_count;
         prev += serversArray->operator[](i);
         i++;
         }*/
        for (int i = 0; i<serversArray->size(); i++) {
            if (val < serversArray->operator[](i)+prev) {
                serverIndex = i+1;
                flow_count++;
                flowIndex = flow_count;
                break;
            }
            else prev += serversArray->operator[](i);
        }
    }
    
    b_value = b_map->operator[](b_key);
    b_value.first = flowIndex;
    b_value.second = serverIndex;
    b_map->operator[](b_key) = b_value;
    
    stringstream ss;
    ss << header->ts.tv_sec;
    string ts = ss.str();
    ts +=".";
    ss.str("");
    ss << header->ts.tv_usec;
    ts += ss.str();
    
    get<0>(s_value) = packet_count;
    get<1>(s_value) = ts;
    get<2>(s_value) = b_key;
    get<3>(s_value) = ntohs(ip->ip_len);
    
    serv_value = s_map->operator[](serverIndex);
    serv_value.push_back(s_value);
    s_map->operator[](serverIndex) = serv_value;
    
    p_key = packet_count;
    p_map->insert(make_pair(p_key, b_value));
    
    packet_count++;
    
    return;
}
