//
// Created by dsliwinski on 12/19/2023.
//
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <argp.h>
#include <signal.h>


#define MAX_INDEX_ENTRIES                   5
#define MAP_ROOT_FS                         "/run/xdp/maps"
#define MAX_DNS_CHARS                       255


bool add = false;
bool clear = false;
bool list = false;

union bpf_attr domain_map;
char *program_name;
int domain_fd = -1;
char *private_domain_name;

const char *domain_map_path = MAP_ROOT_FS"/domain_map";
const char *argp_program_version = "0.1.0";

struct dns_name_struct {
    char dns_name[MAX_DNS_CHARS];
    __uint8_t dns_length;
};

void open_domain_map();
void usage(char *message);
void close_maps(int code);

void INThandler(int sig){
    signal(sig, SIG_IGN);
    close_maps(1);
}

void map_update() {
    if(domain_fd == -1){
        open_domain_map();
    }
    uint32_t key = 0;
    struct dns_name_struct domain_name;
    domain_map.map_fd = domain_fd;
    domain_map.flags = BPF_ANY;
    domain_map.key = (uint64_t)&key;
    domain_map.value = (uint64_t)&domain_name;
    for (int x=0; x < MAX_INDEX_ENTRIES; x++) {
        key = x;
        domain_map.key = (uint64_t)&key;
        int ret = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &domain_map, sizeof(domain_map));
        if (ret) {
            printf("MAP_LOOKUP_ELEM: %s \n", strerror(errno));
            break;
        }
        if (strcmp(domain_name.dns_name, private_domain_name) == 0) {
            printf("@key %d - entry %s already exists.\n", key, private_domain_name);
            break;
        } else if (strlen(domain_name.dns_name) == 0) {
            printf("@key %d - no entry, adding new entry %s.\n", key, private_domain_name);
            int domain_suffix_length = sprintf(domain_name.dns_name, "%s", private_domain_name);
            domain_name.dns_length = domain_suffix_length;
            int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &domain_map, sizeof(domain_map));
            if (ret) {
                printf("MAP_UPDATE_ELEM: %s\n", strerror(errno));
            }
            break;
        } else if (key == (MAX_INDEX_ENTRIES-1)) {
            printf("@key %d - found suffix %s, replacing it with %s\n", key, domain_name.dns_name, private_domain_name);
            int domain_suffix_length = sprintf(domain_name.dns_name, "%s", private_domain_name);
            domain_name.dns_length = domain_suffix_length;
            int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &domain_map, sizeof(domain_map));
            if (ret) {
                printf("MAP_UPDATE_ELEM: %s\n", strerror(errno));
            }
            break;
        } else {
            printf("Continue to traverse the map");
        }
    }
    close(domain_fd);
}

void map_clear() {
    if(domain_fd == -1){
        open_domain_map();
    }
    uint32_t key = 0;
    struct dns_name_struct domain_name;
    domain_map.map_fd = domain_fd;
    domain_map.flags = BPF_ANY;
    domain_map.key = (uint64_t)&key;
    domain_map.value = (uint64_t)&domain_name;
    for (int x=0; x < MAX_INDEX_ENTRIES; x++) {
        key = x;
        domain_map.key = (uint64_t)&key;
        int ret = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &domain_map, sizeof(domain_map));
        if (ret) {
            printf("MAP_LOOKUP_ELEM: %s \n", strerror(errno));
            break;
        }
        if (strlen(domain_name.dns_name) > 0) {
            printf("domain suffix is %s @key %d.\n", domain_name.dns_name, key);
            printf("domain suffix length is %d @key %d.\n", domain_name.dns_length, key);
            if (strcmp(domain_name.dns_name, private_domain_name) == 0) {
                domain_name.dns_length = 0;
                sprintf(domain_name.dns_name, "%s", "");
                int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &domain_map, sizeof(domain_map));
                if (ret)
                {
                    printf("BPF_MAP_UPDATE_ELEM: %s \n", strerror(errno));
                }
                printf("@key %d - value cleared\n", key);
                break;
            } else {
                printf("@key %d - given value is not the same\n", key);
            }
        } else {
            printf("@key %d - no entry\n", key);
        }
    }
    close(domain_fd);
}

void map_list() {
    if (domain_fd == -1) {
        open_domain_map();
    }
    struct dns_name_struct domain_name;
    uint32_t key = 0;
    domain_map.map_fd = domain_fd;
    domain_map.flags = BPF_ANY;
    domain_map.value = (uint64_t)&domain_name;
    domain_map.key = (uint64_t)&key;
    for (int x=0; x < MAX_INDEX_ENTRIES; x++) {
        key = x;
        domain_map.key = (uint64_t)&key;
        int ret = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &domain_map, sizeof(domain_map));
        if (ret) {
            printf("MAP_LOOKUP_ELEM: %s \n", strerror(errno));
            break;
        }
        if (strlen(domain_name.dns_name) > 0) {
            printf("domain suffix is %s @key %d.\n", domain_name.dns_name, key);
            printf("domain suffix length is %d @key %d.\n", domain_name.dns_length, key);
        } else {
            printf("@key %d - no entry\n", key);
        }
    }
    close(domain_fd);
}

// commandline parser options
static struct argp_option options[] = {
        {"add", 'A', NULL, 0, "Add private domain suffix", 0},
        {"remove", 'R', NULL, 0, "Remove private domain suffix", 0},
        {"list", 'L', NULL, 0, "List private domain suffix", 0},
        {"private_domain_name", 'S', "", 0, "Enter private domain suffix", 0},
        {0}
};


static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    program_name = state->name;
    switch (key)
    {
        case 'R':
            clear = true;
            break;
        case 'A':
            add = true;
            break;
        case 'L':
            list = true;
            break;
        case 'S':
            private_domain_name = arg;
            if (strlen(private_domain_name) > 253) {
                printf("domain is %lu, which is larger than 253", strlen(private_domain_name));
                exit(1);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp argp = {options, parse_opt, 0, 0, 0, 0, 0};

void close_maps(int code){
    if(domain_fd != -1){
        close(domain_fd);
    }
    domain_fd = -1;
    exit(code);
}

void open_domain_map(){

    /* open BPF domain_map */
    memset(&domain_map, 0, sizeof(domain_map));
    /* set path name with location of map in filesystem */
    domain_map.pathname = (uint64_t)domain_map_path;
    domain_map.bpf_fd = 0;
    domain_map.file_flags = 0;
    /* make system call to get fd for map */
    domain_fd = syscall(__NR_bpf, BPF_OBJ_GET, &domain_map, sizeof(domain_map));
    if (domain_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
}

void usage(char *message)
{
    fprintf(stderr, "%s : %s\n", program_name, message);
    fprintf(stderr, "Usage: zfw-dns -I -S <private domain name>\n");
    fprintf(stderr, "       zfw-dns -D -S <private domain name>\n");
    fprintf(stderr, "       zfw-dns -L\n");
    fprintf(stderr, "       zfw-dns --help\n");
    exit(1);
}


int main(int argc, char **argv)
{
    signal(SIGINT, INThandler);
    signal(SIGTERM, INThandler);
    argp_parse(&argp, argc, argv, 0, 0, 0);

    if (add) {
        map_update();
    }
    else if (clear) {
        map_clear();
    }
    else if (list) {
        map_list();
    } else {
        usage("No arguments specified");
    }
    close_maps(0);
}