/*
 * knob_reader - TE300K rotary knob + buttons -> authenticated UDP
 * ================================================================
 * Reads /dev/input/event4 ("channel-switch") for knob rotation and
 * /dev/input/event3 ("gpio-keys") for emergency/ident buttons.
 * Sends HMAC-signed UDP packets to the channel switcher bot.
 *
 * Packet format (45 bytes):
 *   [0]      command: 'N' (next), 'P' (prev), 'E' (emergency), 'I' (ident)
 *   [1..8]   radio_id: 8-char identifier (null-padded)
 *   [9..12]  timestamp: uint32 big-endian (unix epoch)
 *   [13..44] HMAC-SHA256 over bytes [0..12]
 *
 * Usage: knob_reader <bot_host> <bot_port> <radio_id> <secret>
 * Example: knob_reader 192.168.1.100 4378 radio01 mySecretKey123
 *
 * Or with config file:
 *   knob_reader -f /data/local/tmp/knob.conf
 *
 * Config file format (one key=value per line):
 *   host=192.168.1.100
 *   port=4378
 *   radio_id=radio01
 *   secret=mySecretKey123
 *   device=/dev/input/event4
 *   button_device=/dev/input/event3
 *
 * Build: arm-linux-gnueabihf-gcc -static -o knob_reader knob_reader.c
 *
 * License: GPLv3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/input.h>

/* ---- Minimal SHA-256 + HMAC-SHA256 (no OpenSSL needed) ---- */

typedef struct {
    unsigned int state[8];
    unsigned long long count;
    unsigned char buf[64];
} sha256_ctx;

static const unsigned int sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define S1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define s0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define s1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static void sha256_transform(sha256_ctx *ctx, const unsigned char *data) {
    unsigned int a,b,c,d,e,f,g,h,t1,t2,w[64];
    int i;
    for (i=0;i<16;i++)
        w[i]=(data[i*4]<<24)|(data[i*4+1]<<16)|(data[i*4+2]<<8)|data[i*4+3];
    for (i=16;i<64;i++)
        w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i=0;i<64;i++) {
        t1=h+S1(e)+CH(e,f,g)+sha256_k[i]+w[i];
        t2=S0(a)+MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
    ctx->count=0;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, unsigned int len) {
    unsigned int i, idx;
    idx = (unsigned int)(ctx->count % 64);
    ctx->count += len;
    for (i=0; i<len; i++) {
        ctx->buf[idx++] = data[i];
        if (idx == 64) { sha256_transform(ctx, ctx->buf); idx=0; }
    }
}

static void sha256_final(sha256_ctx *ctx, unsigned char hash[32]) {
    unsigned int idx = (unsigned int)(ctx->count % 64);
    unsigned long long bits = ctx->count * 8;
    int i;
    ctx->buf[idx++] = 0x80;
    if (idx > 56) { while(idx<64) ctx->buf[idx++]=0; sha256_transform(ctx,ctx->buf); idx=0; }
    while(idx<56) ctx->buf[idx++]=0;
    for (i=7;i>=0;i--) ctx->buf[56+(7-i)]=(unsigned char)(bits>>(i*8));
    sha256_transform(ctx, ctx->buf);
    for (i=0;i<8;i++) {
        hash[i*4]=(ctx->state[i]>>24)&0xff;
        hash[i*4+1]=(ctx->state[i]>>16)&0xff;
        hash[i*4+2]=(ctx->state[i]>>8)&0xff;
        hash[i*4+3]=ctx->state[i]&0xff;
    }
}

static void sha256_raw(const unsigned char *data, unsigned int len, unsigned char hash[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}

static void hmac_sha256(const unsigned char *key, unsigned int keylen,
                        const unsigned char *msg, unsigned int msglen,
                        unsigned char out[32]) {
    unsigned char kpad[64], ipad[64], opad[64], khash[32], inner[32];
    sha256_ctx ctx;
    unsigned int i;
    if (keylen > 64) { sha256_raw(key, keylen, khash); key = khash; keylen = 32; }
    memset(kpad, 0, 64);
    memcpy(kpad, key, keylen);
    for (i=0; i<64; i++) { ipad[i] = kpad[i] ^ 0x36; opad[i] = kpad[i] ^ 0x5c; }
    sha256_init(&ctx); sha256_update(&ctx, ipad, 64); sha256_update(&ctx, msg, msglen); sha256_final(&ctx, inner);
    sha256_init(&ctx); sha256_update(&ctx, opad, 64); sha256_update(&ctx, inner, 32); sha256_final(&ctx, out);
}

/* ---- End crypto ---- */

/* TE300K knob keycodes (channel-switch on /dev/input/event4) */
#define KNOB_CW         184   /* KEY_F14 = clockwise = next */
#define KNOB_CCW        183   /* KEY_F13 = counter-clockwise = prev */

/* TE300K button keycodes (gpio-keys on /dev/input/event3) */
#define BTN_EMERGENCY   61    /* KEY_F3 = emergency button */
#define BTN_IDENT       60    /* KEY_F2 = side/ident button */

/* Packet constants */
#define PKT_SIZE        45
#define RADIO_ID_LEN    8
#define HMAC_OFFSET     13
#define PAYLOAD_LEN     13

/* Command bytes */
#define CMD_NEXT        'N'
#define CMD_PREV        'P'
#define CMD_EMERGENCY   'E'
#define CMD_IDENT       'I'

#define DEBOUNCE_MS     150

/* Config */
static char cfg_host[256]  = "";
static int  cfg_port       = 4378;
static char cfg_radio_id[RADIO_ID_LEN + 1] = "";
static char cfg_secret[256] = "";
static char cfg_device[256] = "/dev/input/event4";
static char cfg_button_device[256] = "/dev/input/event3";

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void build_packet(unsigned char pkt[PKT_SIZE], char cmd) {
    unsigned int ts;
    struct timespec now;
    pkt[0] = (unsigned char)cmd;
    memset(pkt + 1, 0, RADIO_ID_LEN);
    strncpy((char *)(pkt + 1), cfg_radio_id, RADIO_ID_LEN);
    clock_gettime(CLOCK_REALTIME, &now);
    ts = (unsigned int)now.tv_sec;
    pkt[9]  = (ts >> 24) & 0xff;
    pkt[10] = (ts >> 16) & 0xff;
    pkt[11] = (ts >> 8)  & 0xff;
    pkt[12] = ts & 0xff;
    hmac_sha256((const unsigned char *)cfg_secret, strlen(cfg_secret),
                pkt, PAYLOAD_LEN, pkt + HMAC_OFFSET);
}

static int send_command(int sock_fd, struct sockaddr_in *dest,
                        unsigned char pkt[PKT_SIZE], char cmd,
                        const char *label, long long *last_send) {
    long long now = now_ms();
    if (now - *last_send < DEBOUNCE_MS) return 0;
    *last_send = now;
    build_packet(pkt, cmd);
    if (sendto(sock_fd, pkt, PKT_SIZE, 0,
               (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
        return -1;
    }
    printf("knob_reader: %s (%s)\n", label, cfg_radio_id);
    fflush(stdout);
    return 1;
}

static void load_config(const char *path) {
    FILE *f = fopen(path, "r");
    char line[512], key[64], val[256];
    if (!f) { fprintf(stderr, "Cannot open config: %s\n", path); exit(1); }
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        if (sscanf(line, " %63[^=]=%255[^\r\n]", key, val) == 2) {
            if (strcmp(key, "host") == 0) strncpy(cfg_host, val, sizeof(cfg_host)-1);
            else if (strcmp(key, "port") == 0) cfg_port = atoi(val);
            else if (strcmp(key, "radio_id") == 0) strncpy(cfg_radio_id, val, RADIO_ID_LEN);
            else if (strcmp(key, "secret") == 0) strncpy(cfg_secret, val, sizeof(cfg_secret)-1);
            else if (strcmp(key, "device") == 0) strncpy(cfg_device, val, sizeof(cfg_device)-1);
            else if (strcmp(key, "button_device") == 0) strncpy(cfg_button_device, val, sizeof(cfg_button_device)-1);
        }
    }
    fclose(f);
}

int main(int argc, char *argv[]) {
    int knob_fd, btn_fd, sock_fd;
    struct sockaddr_in dest;
    struct input_event ev;
    long long last_knob_send = 0;
    long long last_btn_send = 0;
    unsigned char pkt[PKT_SIZE];
    struct pollfd fds[2];
    int nfds;

    if (argc == 3 && strcmp(argv[1], "-f") == 0) {
        load_config(argv[2]);
    } else if (argc == 5) {
        strncpy(cfg_host, argv[1], sizeof(cfg_host)-1);
        cfg_port = atoi(argv[2]);
        strncpy(cfg_radio_id, argv[3], RADIO_ID_LEN);
        strncpy(cfg_secret, argv[4], sizeof(cfg_secret)-1);
    } else {
        fprintf(stderr,
            "Usage:\n"
            "  %s <host> <port> <radio_id> <secret>\n"
            "  %s -f <config_file>\n", argv[0], argv[0]);
        return 1;
    }

    if (!cfg_host[0] || !cfg_radio_id[0] || !cfg_secret[0]) {
        fprintf(stderr, "Error: host, radio_id, and secret are required\n");
        return 1;
    }

    /* Open knob device */
    knob_fd = open(cfg_device, O_RDONLY);
    if (knob_fd < 0) {
        fprintf(stderr, "Cannot open knob device %s: %s\n",
                cfg_device, strerror(errno));
        return 1;
    }

    /* Open button device (optional) */
    btn_fd = open(cfg_button_device, O_RDONLY);
    if (btn_fd < 0) {
        fprintf(stderr, "Warning: cannot open button device %s: %s "
                "(emergency/ident disabled)\n",
                cfg_button_device, strerror(errno));
    }

    /* UDP socket */
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        close(knob_fd);
        if (btn_fd >= 0) close(btn_fd);
        return 1;
    }

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(cfg_port);
    if (inet_aton(cfg_host, &dest.sin_addr) == 0) {
        fprintf(stderr, "Invalid address: %s\n", cfg_host);
        close(knob_fd);
        if (btn_fd >= 0) close(btn_fd);
        close(sock_fd);
        return 1;
    }

    printf("knob_reader: knob=%s buttons=%s radio=%s\n",
           cfg_device,
           btn_fd >= 0 ? cfg_button_device : "(disabled)",
           cfg_radio_id);
    printf("knob_reader: target=%s:%d (HMAC-SHA256)\n", cfg_host, cfg_port);
    printf("knob_reader: commands: N(ext) P(rev) E(mergency) I(dent)\n");
    fflush(stdout);

    /* Set up poll */
    fds[0].fd = knob_fd;
    fds[0].events = POLLIN;
    nfds = 1;

    if (btn_fd >= 0) {
        fds[1].fd = btn_fd;
        fds[1].events = POLLIN;
        nfds = 2;
    }

    while (1) {
        int ret = poll(fds, nfds, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "poll: %s\n", strerror(errno));
            break;
        }

        /* Knob events (event4: channel-switch) */
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(knob_fd, &ev, sizeof(ev));
            if (n < (ssize_t)sizeof(ev)) {
                if (n < 0 && errno == EINTR) continue;
                fprintf(stderr, "Knob read error: %s\n", strerror(errno));
                break;
            }
            if (ev.type == EV_KEY && ev.value == 1) {
                if (ev.code == KNOB_CW)
                    send_command(sock_fd, &dest, pkt, CMD_NEXT,
                                 "NEXT", &last_knob_send);
                else if (ev.code == KNOB_CCW)
                    send_command(sock_fd, &dest, pkt, CMD_PREV,
                                 "PREV", &last_knob_send);
            }
        }

        /* Button events (event3: gpio-keys) */
        if (nfds > 1 && (fds[1].revents & POLLIN)) {
            ssize_t n = read(btn_fd, &ev, sizeof(ev));
            if (n < (ssize_t)sizeof(ev)) {
                if (n < 0 && errno == EINTR) continue;
                fprintf(stderr, "Button read error: %s\n", strerror(errno));
                break;
            }
            if (ev.type == EV_KEY && ev.value == 1) {
                if (ev.code == BTN_EMERGENCY)
                    send_command(sock_fd, &dest, pkt, CMD_EMERGENCY,
                                 "EMERGENCY", &last_btn_send);
                else if (ev.code == BTN_IDENT)
                    send_command(sock_fd, &dest, pkt, CMD_IDENT,
                                 "IDENT", &last_btn_send);
            }
        }
    }

    close(sock_fd);
    close(knob_fd);
    if (btn_fd >= 0) close(btn_fd);
    return 0;
}
