//
// Created by dsliwinski on 12/19/2023.
//
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <string.h>

#define DNS_PORT        53
#define MAX_QDCOUNT     1
#define MAX_DNS_CHARS   255
#define MAX_ALLOWED_CHARS 64
#define MAX_INDEX_ENTRIES 5

struct dns_name_struct {
    char dns_name[MAX_DNS_CHARS];
    uint8_t dns_length;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct dns_name_struct));
    __uint(max_entries, MAX_INDEX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct dns_name_struct));
    __uint(max_entries, MAX_INDEX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_map SEC(".maps");

/* The DNS message header. */
struct dnshdr {
    uint16_t id;
    uint8_t flags1, flags2;
#define DNS_FLAG1_RESPONSE        0x80
#define DNS_FLAG1_OPCODE_STATUS   0x10
#define DNS_FLAG1_OPCODE_INVERSE  0x08
#define DNS_FLAG1_OPCODE_STANDARD 0x00
#define DNS_FLAG1_AUTHORATIVE     0x04
#define DNS_FLAG1_TRUNC           0x02
#define DNS_FLAG1_RD              0x01
#define DNS_FLAG2_RA              0x80
#define DNS_FLAG2_ERR_MASK        0x0f
#define DNS_FLAG2_ERR_NONE        0x00
#define DNS_FLAG2_ERR_NAME        0x03
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
/* The question section structure. */
struct dns_question_section {
    char qname[MAX_DNS_CHARS];
    uint16_t qtype;
    uint16_t qclass;
};
/* The resource record (i.e. answer, authority, additional sections) structure. */
struct dns_resource_record {
    /* DNS answer record starts with either a domain name or a pointer
       to a name already present somewhere in the packet. */
    char name[MAX_DNS_CHARS];
    uint16_t type;
    uint16_t class;
    uint16_t ttl[2];
    uint16_t rdlength;
    uint8_t ipaddr[4];
};

/* get entry from domain_map map */
static inline struct dns_name_struct *get_domain_name(const uint32_t key){
    struct dns_name_struct* domain_name = bpf_map_lookup_elem(&domain_map, &key);
    return domain_name;
}

/* get the length of dns question name */
static inline struct dns_name_struct *get_dns(const int index, const void *dns_question) {
    struct dns_name_struct *dns_name = NULL;
    dns_name = bpf_map_lookup_elem(&dns_map, &index);
    if(dns_name){
        const long length = bpf_probe_read_kernel_str((void *)&dns_name->dns_name, sizeof(dns_name->dns_name), dns_question);
        // bpf_printk("answer=%d",length);
        // if (length > 0) {
        //     for (int i = 0; i < length; i++) {
        //         bpf_printk(":%c", dns_name->dns_name[i]);
        //     }
        // }
        dns_name->dns_length = length;
    }else{
        bpf_printk("no map entry found");
    }
    return dns_name;
}

static inline int compare_domain_names(const struct dns_name_struct *dnc, const struct dns_name_struct *dni) {
    //const uint8_t dni_reverse_start = dni->dns_length - dnc->dns_length - 1;
    /* check if the configured domain length is not more than MAX_ALLOWED_CHARS chars long */
    int y =0; /* character counter */
    for (int z = 0; z < MAX_ALLOWED_CHARS; z++) {
        /* Point to the last char of each string to start counting */
        const uint8_t dni_reverse_start = dni->dns_length - 2 - z;
        const uint8_t dnc_reverse_start = dnc->dns_length - 2 - z;
        // bpf_printk("char count is %d", y);
        // bpf_printk("z is %d", z);
        // bpf_printk("dnc->dns_length is %d", dnc->dns_length);
        /* if custom domain char is a dot and intercepted domain name char is dot in form of char count */
        if (dnc->dns_name[dnc_reverse_start] == '.' && dni->dns_name[dni_reverse_start] == y) {
            // bpf_printk("dni start char is %x", dni->dns_name[dni_reverse_start]);
            // bpf_printk("dnc start char is %x", dnc->dns_name[dnc_reverse_start]);
            /* reset character counter for domain/subdomain */
            y=0;
        /* if custom domain reached its length and intercepted domain char is dot in form of char count */
        } else if (dnc->dns_length == z+1 && dni->dns_name[dni_reverse_start] == y) {
            // bpf_printk("dni start char is %x", dni->dns_name[dni_reverse_start]);
            // bpf_printk("dnc start char is %x", dnc->dns_name[dnc_reverse_start]);
             break;
        /* if custom domain and intercepted domain chars are not the same */
        } else if (dni->dns_name[dni_reverse_start] != dnc->dns_name[dnc_reverse_start]) {
            return 1;
        /* if neither of the previous asks are true, then increase the char counter and continue to compare chars  */
        } else {
            y++;
        }
    }
    return 0;
}

static inline uint16_t ip_checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }
    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

/* Main ebpf program */
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {

    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(ctx->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)ctx->data_end){
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr *)(ctx->data + sizeof(*eth));
    /* ensure ip header is in packet bounds */
    if ((unsigned long)(iph + 1) > (unsigned long)ctx->data_end){
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    struct udphdr *udph = (struct udphdr *)((unsigned long)iph + sizeof(*iph));
    if ((unsigned long)(udph + 1) > (unsigned long)ctx->data_end){
        return XDP_PASS;
    }

    if (udph->dest != bpf_htons(DNS_PORT)) {
        return XDP_PASS;
    }
    // bpf_printk("port is %ld", bpf_htons(udph->dest));
    struct dnshdr *dnsh = (struct dnshdr *)((unsigned long)udph + sizeof(*udph));
    if ((unsigned long)(dnsh + 1) > (unsigned long)ctx->data_end){
        return XDP_PASS;
    }

    /* Initial dns payload pointer */
    __u8 *dns_payload = (__u8 *)((unsigned long)dnsh + sizeof(*dnsh));
    if ((unsigned long)(dns_payload + 1) > (unsigned long)ctx->data_end) {
        return XDP_PASS;
    }
    // bpf_printk("question byte is %d", bpf_htons(dnsh->qdcount));
    // bpf_printk("answer byte is %d", bpf_htons(dnsh->ancount));
    // bpf_printk("name servers byte is %d", bpf_htons(dnsh->nscount));
    // bpf_printk("additional records byte is %d", bpf_htons(dnsh->arcount));
    /* logic to find dns name string */
    if (bpf_htons(dnsh->qdcount) != 0 && bpf_htons(dnsh->ancount) == 0) {
        // bpf_printk("in max_qdcount before loop");
        for (int x = 0; x < MAX_QDCOUNT; x++) {
            // bpf_printk("in max_qdcount loop");
            /* get interceptes domain name from interface */
            const struct dns_name_struct *domain_name_intercepted = get_dns(x, dns_payload);
            if (domain_name_intercepted && domain_name_intercepted->dns_length > 0) {
            for (int y = 0; y < MAX_INDEX_ENTRIES; y++) {
                /* get private domain name from map */
                const struct dns_name_struct *domain_name_configured = get_domain_name(y);
                if (domain_name_configured && domain_name_configured->dns_name[0] != '\0') {
                    const int result = compare_domain_names(domain_name_configured, domain_name_intercepted);
                    // bpf_printk("result is %d", result);
                    if (result == 0) {
                        // __uint8_t dst_mac[6];
                        // for (int z=0; z < 6; z++) {
                        //     dst_mac[z] = 0x00;
                        // }
                        bpf_printk("found entry is same");
                        // iph->daddr = bpf_htonl(0x7f000001);
                        // iph->daddr = bpf_htonl(0x0a60179d);
                        // iph->check = 0;
                        // iph->check = ip_checksum((__u16 *)iph, sizeof(struct iphdr));
                        // memcpy(&eth->h_dest, &dst_mac,sizeof(eth->h_dest));
                        // // memcpy(&eth->h_source, &tus->dest,6);
                        // return bpf_redirect(1, 0);
                    } else {
                        // bpf_printk("found entry is not same");
                    }
                } else {
                    // bpf_printk("no entry found");
                }
            }
                /* Move dns payload pointer to next question or section */
                dns_payload = (dns_payload + domain_name_intercepted->dns_length + 4);
            } else {
                bpf_printk("answer was not positive, breaking out of the inner loop");
                break;
            }
        }
    }
    /* Pass the packet on the networking stack */
    return XDP_PASS;
}
SEC("license") const char __license[] = "Dual BSD/GPL";