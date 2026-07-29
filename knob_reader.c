/*
 * porto-watchdog - TE300K local watchdog daemon
 * ==============================================
 * Runs in the background on the TE300K radio, intercepts ALL hardware
 * key events, and routes them:
 *
 *   LOCAL (PTT → Mumla via pttbridge.apk socket):
 *     /dev/input/event2  KEY_F1 (59)  = RSM PTT press/release (telo_ptt)
 *     /dev/input/event3  KEY_F1 (59)  = Body PTT press/release (gpio-keys)
 *
 *   REMOTE (UDP → porto-watchdog server container):
 *     /dev/input/event3  KEY_F2 (60)  = Ident broadcast
 *     /dev/input/event3  KEY_F3 (61)  = Emergency broadcast (the RSM's
 *                        emergency button also surfaces here, NOT on
 *                        event2 - verified on real hardware)
 *     + a minutely 'H' heartbeat packet (same 45-byte format) that
 *       keeps the NAT return path open for server replies
 *
 *   INBOUND (server → radio, same UDP socket):
 *     'C' channel packet (77 bytes): cmd(1) + radio_id(8) + ts(4) +
 *     name field(32) + HMAC-SHA256(32) over bytes [0..44]. The name
 *     field holds the channel name and, space permitting, the radio's
 *     callsign as a second null-terminated string. Verified (id +
 *     HMAC + 30s replay window) and written to
 *     /data/local/tmp/screenvars.txt as key=value lines (channel=,
 *     id=), which the patched Te300k idle screen displays
 *     ("Channel: X" / "Disconnected" + "ID: <callsign>"). Empty
 *     channel = our user is not connected to Mumble.
 *     /dev/input/event4  KEY_F13 (183) = Previous channel
 *     /dev/input/event4  KEY_F14 (184) = Next channel
 *     GPS fixes from pttbridge.apk (abstract socket "porto_loc")
 *       = position report ('L' packet, forwarded to TAK by the server)
 *
 * The binary is launched on boot by pttbridge.apk and stays resident.
 * If /data/local/tmp/knob.conf exists, remote watchdog features are
 * enabled. Otherwise it runs in PTT-only mode.
 *
 * GPS reporting is opt-in per radio: it only activates when
 * /data/local/tmp/loc.conf exists (single integer: interval in
 * seconds, read by pttbridge.apk, which owns the GPS receiver).
 *
 * Key packet format (45 bytes, HMAC-SHA256 signed):
 *   [0]      command: 'N'/'P'/'E'/'I'
 *   [1..8]   radio_id: 8-char identifier (null-padded)
 *   [9..12]  timestamp: uint32 big-endian (unix epoch)
 *   [13..44] HMAC-SHA256 over bytes [0..12]
 *
 * Location packet format (64 bytes, encrypted + HMAC-SHA256 signed):
 *   [0]      command: 'L'
 *   [1..8]   radio_id: 8-char identifier (null-padded)
 *   [9..12]  timestamp: uint32 big-endian (unix epoch)
 *   [13..16] salt: 4 random bytes (per-packet nonce component)
 *   [17..31] position block, encrypted (see below). Plaintext layout:
 *              [0..3]   latitude:  int32 BE, degrees * 1e7
 *              [4..7]   longitude: int32 BE, degrees * 1e7
 *              [8..9]   altitude:  int16 BE, meters
 *              [10..11] speed:     uint16 BE, 0.1 m/s units
 *              [12..13] course:    uint16 BE, 0.1 degree units
 *              [14]     accuracy:  uint8, meters (255 = unknown)
 *   [32..63] HMAC-SHA256 over bytes [0..31] (encrypt-then-MAC)
 *
 * Position encryption (radios roam public networks; coordinates must
 * not be readable in transit): keystream = HMAC-SHA256(K_enc,
 * bytes[0..16]) XORed over the position block, with
 * K_enc = HMAC-SHA256(secret, "porto-loc-enc-v1"). The per-packet
 * timestamp+salt make the keystream unique; the radio_id in the
 * header separates keystreams between radios sharing one secret.
 * Everything derives from the secret already in knob.conf - no
 * extra keys to manage.
 *
 * Build: arm-linux-gnueabihf-gcc -static -o porto-watchdog knob_reader.c
 *
 * License: GPLv3
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
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

/* TE300K keycodes */
#define KEY_PTT         59    /* KEY_F1 = PTT button (event3) */
#define BTN_IDENT       60    /* KEY_F2 = side/ident button (event3) */
#define BTN_EMERGENCY   61    /* KEY_F3 = emergency button (event3) */
#define KNOB_CCW        183   /* KEY_F13 = knob counter-clockwise (event4) */
#define KNOB_CW         184   /* KEY_F14 = knob clockwise (event4) */

/* UDP packet constants */
#define PKT_SIZE        45
#define RADIO_ID_LEN    8
#define HMAC_OFFSET     13
#define PAYLOAD_LEN     13

/* Location packet constants */
#define LOC_PKT_SIZE    64
#define LOC_PAYLOAD_LEN 32     /* signed region: header + ciphertext */
#define LOC_HDR_LEN     17     /* cmd + radio_id + timestamp + salt */
#define LOC_CIPHER_LEN  15     /* encrypted position block */
#define LOC_KDF_LABEL   "porto-loc-enc-v1"

/* Command bytes (UDP) */
#define CMD_NEXT        'N'
#define CMD_PREV        'P'
#define CMD_EMERGENCY   'E'
#define CMD_IDENT       'I'
#define CMD_LOC         'L'
#define CMD_HEARTBEAT   'H'

/* Server -> radio channel packet */
#define CHANNEL_PKT_SIZE   77   /* cmd + radio_id + ts + name(32) + HMAC */
#define CHANNEL_NAME_LEN   32
#define CHANNEL_SIGNED_LEN 45   /* bytes covered by the HMAC */
#define SCREENVARS_FILE "/data/local/tmp/screenvars.txt"
#define HEARTBEAT_MS    60000
#define CHANNEL_REPLAY_S   30

#define DEBOUNCE_MS     150

/* Min interval between forwarded GPS fixes (protects the server even
 * if the APK-side interval is misconfigured) */
#define LOC_MIN_MS      5000

/* PTT socket name (abstract namespace, must match pttbridge.apk) */
#define PTT_SOCKET_NAME "ptt_bridge"

/* Location socket name (abstract namespace, we listen, pttbridge.apk
 * connects and writes one "lat lon alt speed bearing accuracy" line
 * per GPS fix) */
#define LOC_SOCKET_NAME "porto_loc"

/* Default config path (auto-loaded if no args given) */
#define DEFAULT_CONFIG  "/data/local/tmp/knob.conf"

/* Config */
static char cfg_host[256]  = "";
static int  cfg_port       = 4378;
static char cfg_radio_id[RADIO_ID_LEN + 1] = "";
static char cfg_secret[256] = "";
static char cfg_device[256] = "/dev/input/event4";           /* knob */
static char cfg_button_device[256] = "/dev/input/event3";    /* body buttons (gpio-keys) */
static char cfg_ptt_device[256] = "/dev/input/event2";       /* RSM PTT (telo_ptt) */

/* Custom APN (optional). Fixes outdated / roaming-incompatible carrier APNs on
 * locked-down radios by writing the operator's correct APN through the
 * platform-signed apn-setter app. custom_apn_mode is the master switch:
 * inert unless custom_apn_mode=true and apn is set. */
static int  cfg_custom_apn_mode = 0;
static char cfg_apn[64] = "";
static char cfg_apn_name[64] = "";
static char cfg_apn_mcc[8] = "";
static char cfg_apn_mnc[8] = "";
static char cfg_apn_protocol[16] = "IPV4V6";
static char cfg_apn_roaming_protocol[16] = "IP";
static char cfg_apn_type[64] = "default,supl";

static int want_udp = 0;     /* config says we should use UDP */
static int udp_enabled = 0;  /* DNS resolved, UDP is working */

/* UDP state (global for lazy DNS retry) */
static int udp_fd = -1;
static struct sockaddr_in udp_dest;
static long long last_dns_attempt = 0;
#define DNS_RETRY_MS 5000

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- PTT socket ---- */

static int ptt_connect(void) {
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* Abstract namespace: first byte is \0, then the name */
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, PTT_SOCKET_NAME, sizeof(addr.sun_path) - 2);

    /* offsetof(sun_path) + 1 + strlen(name) */
    socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(PTT_SOCKET_NAME);

    if (connect(fd, (struct sockaddr *)&addr, len) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int ptt_send(int fd, int pressed) {
    char msg = pressed ? '1' : '0';
    ssize_t n = write(fd, &msg, 1);
    if (n <= 0) return -1;
    return 0;
}

/* ---- Location socket (GPS fixes from pttbridge.apk) ---- */

static int try_resolve_udp(void);   /* defined in the DNS section below */

/* Create the abstract-namespace listening socket for GPS fixes.
 * Returns the listening fd, or -1 on failure (feature disabled). */
static int loc_listen(void) {
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, LOC_SOCKET_NAME, sizeof(addr.sun_path) - 2);

    socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(LOC_SOCKET_NAME);

    if (bind(fd, (struct sockaddr *)&addr, len) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 4) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Round a double to a signed 32-bit int without libm */
static int round_i32(double v) {
    return (int)(v >= 0 ? v + 0.5 : v - 0.5);
}

/* Position-encryption key, derived once from the configured secret */
static unsigned char loc_enc_key[32];
static int loc_enc_key_ready = 0;

static void ensure_loc_enc_key(void) {
    if (loc_enc_key_ready) return;
    hmac_sha256((const unsigned char *)cfg_secret, strlen(cfg_secret),
                (const unsigned char *)LOC_KDF_LABEL, strlen(LOC_KDF_LABEL),
                loc_enc_key);
    loc_enc_key_ready = 1;
}

/* Fill 4 random salt bytes (per-packet nonce component) */
static void loc_salt(unsigned char salt[4]) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, salt, 4);
        close(fd);
        if (n == 4) return;
    }
    /* last-resort fallback, not expected on Android/Linux */
    {
        long long t = now_ms() ^ ((long long)getpid() << 20);
        salt[0] = t & 0xff; salt[1] = (t >> 8) & 0xff;
        salt[2] = (t >> 16) & 0xff; salt[3] = (t >> 24) & 0xff;
    }
}

/* Build the 64-byte 'L' position packet (layout in the header comment).
 * The position block is encrypted (encrypt-then-MAC) so coordinates
 * are not readable on public networks. */
static void build_loc_packet(unsigned char pkt[LOC_PKT_SIZE],
                             double lat, double lon, double alt,
                             float speed, float course, float acc) {
    unsigned int ts;
    struct timespec now;
    unsigned char plain[LOC_CIPHER_LEN];
    unsigned char ks[32];
    int i;
    int lat_i = round_i32(lat * 1e7);
    int lon_i = round_i32(lon * 1e7);
    int alt_i = round_i32(alt);
    int spd_i = round_i32(speed * 10.0);
    int crs_i = round_i32(course * 10.0);
    int acc_i = round_i32(acc);

    if (alt_i >  32767) alt_i =  32767;
    if (alt_i < -32768) alt_i = -32768;
    if (spd_i < 0)      spd_i = 0;
    if (spd_i > 65535)  spd_i = 65535;
    while (crs_i < 0)     crs_i += 3600;
    while (crs_i >= 3600) crs_i -= 3600;
    if (acc_i < 0)   acc_i = 0;
    if (acc_i > 255) acc_i = 255;

    /* Header: cmd + radio_id + timestamp + salt (all authenticated) */
    pkt[0] = (unsigned char)CMD_LOC;
    memset(pkt + 1, 0, RADIO_ID_LEN);
    strncpy((char *)(pkt + 1), cfg_radio_id, RADIO_ID_LEN);
    clock_gettime(CLOCK_REALTIME, &now);
    ts = (unsigned int)now.tv_sec;
    pkt[9]  = (ts >> 24) & 0xff;
    pkt[10] = (ts >> 16) & 0xff;
    pkt[11] = (ts >> 8)  & 0xff;
    pkt[12] = ts & 0xff;
    loc_salt(pkt + 13);

    /* Position block plaintext */
    plain[0]  = ((unsigned int)lat_i >> 24) & 0xff;
    plain[1]  = ((unsigned int)lat_i >> 16) & 0xff;
    plain[2]  = ((unsigned int)lat_i >> 8)  & 0xff;
    plain[3]  = (unsigned int)lat_i & 0xff;
    plain[4]  = ((unsigned int)lon_i >> 24) & 0xff;
    plain[5]  = ((unsigned int)lon_i >> 16) & 0xff;
    plain[6]  = ((unsigned int)lon_i >> 8)  & 0xff;
    plain[7]  = (unsigned int)lon_i & 0xff;
    plain[8]  = ((unsigned int)alt_i >> 8) & 0xff;
    plain[9]  = (unsigned int)alt_i & 0xff;
    plain[10] = ((unsigned int)spd_i >> 8) & 0xff;
    plain[11] = (unsigned int)spd_i & 0xff;
    plain[12] = ((unsigned int)crs_i >> 8) & 0xff;
    plain[13] = (unsigned int)crs_i & 0xff;
    plain[14] = (unsigned char)acc_i;

    /* Encrypt: keystream = HMAC-SHA256(K_enc, header), unique per
     * packet via timestamp+salt (and radio_id for shared secrets) */
    ensure_loc_enc_key();
    hmac_sha256(loc_enc_key, 32, pkt, LOC_HDR_LEN, ks);
    for (i = 0; i < LOC_CIPHER_LEN; i++)
        pkt[LOC_HDR_LEN + i] = plain[i] ^ ks[i];

    /* MAC over header + ciphertext (encrypt-then-MAC) */
    hmac_sha256((const unsigned char *)cfg_secret, strlen(cfg_secret),
                pkt, LOC_PAYLOAD_LEN, pkt + LOC_PAYLOAD_LEN);
}

/* Accept one connection on the loc socket, read a fix line, forward it
 * as a signed UDP packet. Rate-limited to one packet per LOC_MIN_MS. */
static void handle_loc_client(int listen_fd, long long *last_loc_send) {
    char buf[256];
    double lat, lon, alt;
    float speed, course, acc;
    unsigned char pkt[LOC_PKT_SIZE];
    int total = 0;

    int cfd = accept(listen_fd, NULL, NULL);
    if (cfd < 0) return;

    /* The APK writes immediately then closes; don't stall the event
     * loop for more than half a second if it misbehaves */
    struct timeval tv = {0, 500000};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (total < (int)sizeof(buf) - 1) {
        int n = read(cfd, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) break;
        total += n;
        if (memchr(buf, '\n', total)) break;
    }
    close(cfd);
    buf[total] = '\0';

    if (sscanf(buf, "%lf %lf %lf %f %f %f",
               &lat, &lon, &alt, &speed, &course, &acc) != 6)
        return;

    long long now = now_ms();
    if (now - *last_loc_send < LOC_MIN_MS) return;

    if (want_udp && !udp_enabled) try_resolve_udp();
    if (!udp_enabled) return;

    *last_loc_send = now;
    build_loc_packet(pkt, lat, lon, alt, speed, course, acc);
    if (sendto(udp_fd, pkt, LOC_PKT_SIZE, 0,
               (struct sockaddr *)&udp_dest, sizeof(udp_dest)) < 0) {
        fprintf(stderr, "loc sendto: %s\n", strerror(errno));
        return;
    }
    printf("porto-watchdog: LOC %.5f %.5f (%s)\n", lat, lon, cfg_radio_id);
    fflush(stdout);
}

/* ---- UDP packet ---- */

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

/* ---- Android DNS resolution ----
 *
 * glibc static binaries on Android cannot use getaddrinfo() (hangs forever
 * because glibc's NSS can't talk to Android's netd daemon) or popen()
 * (hardcodes /bin/sh which doesn't exist - Android uses /system/bin/sh).
 *
 * Instead we do what c-ares/curl do on Android:
 *   1. Get the DNS server IP from `getprop net.dns1` via fork+exec
 *   2. Send a raw UDP DNS query (RFC 1035) directly to port 53
 *   3. Parse the A record from the response
 *   4. Fall back to 8.8.8.8 / 1.1.1.1 if getprop fails
 *   5. Last resort: fork+exec ping (uses Android's native resolver)
 */

/* Run a command via fork+exec+pipe and read its stdout.
 * Returns bytes read, or -1 on error. */
static int exec_read(const char *prog, char *const argv[], char *buf, int bufsize) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execv(prog, argv);
        _exit(127);
    }

    close(pipefd[1]);
    int total = 0;
    while (total < bufsize - 1) {
        int n = read(pipefd[0], buf + total, bufsize - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    return total;
}

/* Get Android's DNS server from system properties. */
static int get_android_dns(struct in_addr *out) {
    char buf[64];
    char *argv[] = {(char *)"/system/bin/getprop", (char *)"net.dns1", NULL};

    int n = exec_read("/system/bin/getprop", argv, buf, sizeof(buf));
    if (n <= 0) return -1;

    /* Trim trailing whitespace */
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' || buf[n-1] == ' '))
        buf[--n] = '\0';

    if (n == 0) return -1;
    return inet_aton(buf, out) ? 0 : -1;
}

/* Encode hostname for DNS wire format: "a.b.c" → \1a\1b\1c\0 */
static int dns_encode_name(const char *name, unsigned char *buf, int bufsize) {
    const char *p = name;
    int pos = 0;

    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len == 0 || len > 63 || pos + 1 + len >= bufsize) return -1;
        buf[pos++] = (unsigned char)len;
        memcpy(buf + pos, p, len);
        pos += len;
        p += len;
        if (*p == '.') p++;
    }
    if (pos >= bufsize) return -1;
    buf[pos++] = 0;
    return pos;
}

/* Send a raw UDP DNS A-record query and parse the response.
 * Returns 0 on success, -1 on failure. */
static int dns_query_a(struct in_addr dns_server, const char *hostname,
                       struct in_addr *result) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Build query */
    unsigned char qbuf[512];
    int qpos = 0;
    unsigned short txid = (unsigned short)(time(NULL) ^ getpid());

    /* Header */
    qbuf[qpos++] = txid >> 8;   qbuf[qpos++] = txid & 0xFF;
    qbuf[qpos++] = 0x01;        qbuf[qpos++] = 0x00;  /* RD=1 */
    qbuf[qpos++] = 0x00;        qbuf[qpos++] = 0x01;  /* QDCOUNT=1 */
    qbuf[qpos++] = 0x00;        qbuf[qpos++] = 0x00;
    qbuf[qpos++] = 0x00;        qbuf[qpos++] = 0x00;
    qbuf[qpos++] = 0x00;        qbuf[qpos++] = 0x00;

    /* Question: encoded name + QTYPE(A=1) + QCLASS(IN=1) */
    int nlen = dns_encode_name(hostname, qbuf + qpos, sizeof(qbuf) - qpos - 4);
    if (nlen < 0) { close(sock); return -1; }
    qpos += nlen;
    qbuf[qpos++] = 0x00; qbuf[qpos++] = 0x01;  /* A */
    qbuf[qpos++] = 0x00; qbuf[qpos++] = 0x01;  /* IN */

    /* Send to DNS server port 53 */
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    sa.sin_addr = dns_server;

    if (sendto(sock, qbuf, qpos, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(sock);
        return -1;
    }

    /* Receive response */
    unsigned char resp[512];
    int rlen = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
    close(sock);

    if (rlen < 12) return -1;
    /* Verify: same txid, QR=1, RCODE=0 */
    if (resp[0] != qbuf[0] || resp[1] != qbuf[1]) return -1;
    if (!(resp[2] & 0x80)) return -1;
    if ((resp[3] & 0x0F) != 0) return -1;

    int ancount = (resp[6] << 8) | resp[7];
    if (ancount == 0) return -1;

    /* Skip question section */
    int pos = 12;
    while (pos < rlen) {
        if ((resp[pos] & 0xC0) == 0xC0) { pos += 2; break; }
        if (resp[pos] == 0) { pos++; break; }
        pos += 1 + resp[pos];
    }
    pos += 4;  /* QTYPE + QCLASS */

    /* Parse answer records, find first A record */
    int i;
    for (i = 0; i < ancount && pos + 12 <= rlen; i++) {
        /* Skip NAME (pointer or label) */
        if ((resp[pos] & 0xC0) == 0xC0) {
            pos += 2;
        } else {
            while (pos < rlen && resp[pos] != 0) pos += 1 + resp[pos];
            pos++;
        }

        if (pos + 10 > rlen) break;
        int rtype = (resp[pos] << 8) | resp[pos+1];
        int rdlength = (resp[pos+8] << 8) | resp[pos+9];
        pos += 10;

        if (rtype == 1 && rdlength == 4 && pos + 4 <= rlen) {
            memcpy(result, resp + pos, 4);
            return 0;
        }
        pos += rdlength;
    }

    return -1;
}

/* Resolve hostname to IPv4 address.
 * Strategy: raw IP → Android DNS → Google/Cloudflare DNS → ping fallback.
 * Returns 0 on success, -1 on failure. */
static int resolve_hostname(const char *hostname, struct in_addr *out) {
    struct in_addr dns_server;

    /* Fast path: already an IP address */
    if (inet_aton(hostname, out))
        return 0;

    /* Try Android's configured DNS server (getprop net.dns1) */
    if (get_android_dns(&dns_server) == 0) {
        printf("porto-watchdog: DNS server from Android: %s\n", inet_ntoa(dns_server));
        fflush(stdout);
        if (dns_query_a(dns_server, hostname, out) == 0)
            return 0;
    }

    /* Fallback: well-known public DNS servers */
    inet_aton("8.8.8.8", &dns_server);
    if (dns_query_a(dns_server, hostname, out) == 0)
        return 0;

    inet_aton("1.1.1.1", &dns_server);
    if (dns_query_a(dns_server, hostname, out) == 0)
        return 0;

    /* Last resort: ping via fork+exec (uses Android's bionic resolver) */
    {
        char line[256];
        char *argv[] = {(char *)"/system/bin/ping", (char *)"-c1",
                        (char *)"-W2", (char *)hostname, NULL};

        int n = exec_read("/system/bin/ping", argv, line, sizeof(line));
        if (n > 0) {
            char *op = strchr(line, '(');
            char *cp = op ? strchr(op, ')') : NULL;
            if (op && cp) {
                *cp = '\0';
                if (inet_aton(op + 1, out))
                    return 0;
            }
        }
    }

    return -1;
}

/* Try to resolve DNS and enable UDP. Rate-limited to once per DNS_RETRY_MS.
 * Returns 1 on success, 0 on failure. Safe to call repeatedly. */
static int try_resolve_udp(void) {
    struct in_addr addr;
    long long now = now_ms();

    if (now - last_dns_attempt < DNS_RETRY_MS) return 0;
    last_dns_attempt = now;

    if (udp_fd < 0) {
        udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd < 0) return 0;
    }

    if (resolve_hostname(cfg_host, &addr) == 0) {
        memset(&udp_dest, 0, sizeof(udp_dest));
        udp_dest.sin_family = AF_INET;
        udp_dest.sin_port = htons(cfg_port);
        udp_dest.sin_addr = addr;
        udp_enabled = 1;
        printf("porto-watchdog: resolved %s -> %s:%d - UDP enabled\n",
               cfg_host, inet_ntoa(addr), cfg_port);
        fflush(stdout);
        return 1;
    }
    return 0;
}

static int send_udp_command(int sock_fd, struct sockaddr_in *dest,
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
    printf("porto-watchdog: %s (%s)\n", label, cfg_radio_id);
    fflush(stdout);
    return 1;
}

/* ---- Screen feedback (server -> radio) ----
 * The server replies to every packet we send (including the minutely
 * 'H' heartbeat) with a signed 'C' packet carrying our current Mumble
 * channel name and, space permitting, our callsign. After verification
 * these land in SCREENVARS_FILE as key=value lines (channel=, id=),
 * which the (patched) Te300k idle screen polls. Empty channel = our
 * user is not connected to Mumble; the screen shows "Disconnected".
 *
 * SCREENVARS_FILE must already exist with mode 666 (onboarding does
 * touch + chmod) - /data/local/tmp itself is not writable by our
 * uid, but an existing world-writable file in it is. */
static unsigned int last_channel_ts = 0;

static void handle_channel_packet(void) {
    unsigned char buf[CHANNEL_PKT_SIZE + 16];
    unsigned char mac[32];
    char name[CHANNEL_NAME_LEN + 2];
    unsigned int ts, now;
    size_t len;
    ssize_t n, w;
    int fd;

    n = recvfrom(udp_fd, buf, sizeof(buf), 0, NULL, NULL);
    if (n != CHANNEL_PKT_SIZE || buf[0] != 'C') return;
    if (strncmp((const char *)buf + 1, cfg_radio_id, RADIO_ID_LEN) != 0)
        return;
    hmac_sha256((const unsigned char *)cfg_secret, strlen(cfg_secret),
                buf, CHANNEL_SIGNED_LEN, mac);
    if (memcmp(mac, buf + CHANNEL_SIGNED_LEN, 32) != 0) return;
    ts = ((unsigned int)buf[9] << 24) | ((unsigned int)buf[10] << 16) |
         ((unsigned int)buf[11] << 8) | (unsigned int)buf[12];
    now = (unsigned int)time(NULL);
    if (ts + CHANNEL_REPLAY_S < now || now + CHANNEL_REPLAY_S < ts) return;
    if (ts < last_channel_ts) return;   /* never rewind to an older update */
    last_channel_ts = ts;

    memcpy(name, buf + 13, CHANNEL_NAME_LEN);
    name[CHANNEL_NAME_LEN] = '\0';
    name[CHANNEL_NAME_LEN + 1] = '\0';
    fd = open(SCREENVARS_FILE, O_WRONLY | O_TRUNC | O_CREAT, 0666);
    if (fd < 0) return;
    /* key=value screen variables: channel (empty = disconnected) and
     * id (the callsign; second null-terminated string, if the server
     * sent one). Add more keys here as the screen grows. */
    {
        const char *callsign = "";
        char out[2 * CHANNEL_NAME_LEN + 32];
        int olen;
        len = strlen(name);
        if (len + 1 < CHANNEL_NAME_LEN)
            callsign = name + len + 1;
        olen = snprintf(out, sizeof(out), "channel=%s\nid=%s\n",
                        name, callsign);
        if (olen > 0) {
            w = write(fd, out, (size_t)olen);
            (void)w;
        }
    }
    close(fd);
}

/* ---- Config file ---- */

static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    char line[512], key[64], val[256];
    if (!f) return 0;  /* not found = not an error, just no UDP */
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        if (sscanf(line, " %63[^=]=%255[^\r\n]", key, val) == 2) {
            if (strcmp(key, "host") == 0) strncpy(cfg_host, val, sizeof(cfg_host)-1);
            else if (strcmp(key, "port") == 0) cfg_port = atoi(val);
            else if (strcmp(key, "radio_id") == 0) strncpy(cfg_radio_id, val, RADIO_ID_LEN);
            else if (strcmp(key, "secret") == 0) strncpy(cfg_secret, val, sizeof(cfg_secret)-1);
            else if (strcmp(key, "device") == 0) strncpy(cfg_device, val, sizeof(cfg_device)-1);
            else if (strcmp(key, "button_device") == 0) strncpy(cfg_button_device, val, sizeof(cfg_button_device)-1);
            else if (strcmp(key, "ptt_device") == 0) strncpy(cfg_ptt_device, val, sizeof(cfg_ptt_device)-1);
            else if (strcmp(key, "custom_apn_mode") == 0) cfg_custom_apn_mode = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcmp(val, "yes") == 0);
            else if (strcmp(key, "apn") == 0) strncpy(cfg_apn, val, sizeof(cfg_apn)-1);
            else if (strcmp(key, "apn_name") == 0) strncpy(cfg_apn_name, val, sizeof(cfg_apn_name)-1);
            else if (strcmp(key, "apn_mcc") == 0) strncpy(cfg_apn_mcc, val, sizeof(cfg_apn_mcc)-1);
            else if (strcmp(key, "apn_mnc") == 0) strncpy(cfg_apn_mnc, val, sizeof(cfg_apn_mnc)-1);
            else if (strcmp(key, "apn_protocol") == 0) strncpy(cfg_apn_protocol, val, sizeof(cfg_apn_protocol)-1);
            else if (strcmp(key, "apn_roaming_protocol") == 0) strncpy(cfg_apn_roaming_protocol, val, sizeof(cfg_apn_roaming_protocol)-1);
            else if (strcmp(key, "apn_type") == 0) strncpy(cfg_apn_type, val, sizeof(cfg_apn_type)-1);
        }
    }
    fclose(f);
    return 1;
}

/* Read one Android system property (whitespace-trimmed) into out via getprop.
 * Same fork+exec mechanism as get_android_dns(). Returns trimmed length. */
static int getprop_str(const char *prop, char *out, int outsize) {
    char *argv[] = {(char *)"/system/bin/getprop", (char *)prop, NULL};
    int n = exec_read("/system/bin/getprop", argv, out, outsize);
    if (n <= 0) { out[0] = '\0'; return 0; }
    while (n > 0 && (out[n-1] == '\n' || out[n-1] == '\r' ||
                     out[n-1] == ' '  || out[n-1] == '\t'))
        out[--n] = '\0';
    return n;
}

/* Bounded wait for the SIM to be ready and the modem registered, so the
 * firmware has pulled the operator's default APN profile before we replace it.
 * READY is matched as a substring (multi-SIM builds comma-join per slot), and
 * a non-empty gsm.operator.numeric (serving PLMN) is the reliable "registered"
 * signal. Gives up after 60s and applies anyway. */
static void wait_for_sim(void) {
    char sim[64], num[64];
    int tries;
    for (tries = 0; tries < 60; tries++) {
        int ready = (getprop_str("gsm.sim.state", sim, sizeof(sim)) > 0 &&
                     strstr(sim, "READY") != NULL);
        int reg   = (getprop_str("gsm.operator.numeric", num, sizeof(num)) > 0);
        if (ready && reg) return;
        sleep(1);
    }
    fprintf(stderr, "porto-watchdog: SIM/registration not ready after 60s; "
                    "applying APN anyway\n");
}

/* Apply a custom APN by launching the platform-signed apn-setter app with the
 * settings from knob.conf. No-op unless custom_apn_mode=true and apn is set.
 *
 * Runs in a detached grandchild (double-fork) so the bounded SIM-registration
 * wait never delays the daemon's knob/button/UDP handling. Called once at
 * startup which - via the pttbridge boot autostart - happens on every boot, so
 * the APN is re-applied after the firmware re-seeds its own default each boot.
 * The apn-setter app disables every other APN itself, so no 'disable' extra. */
static void apply_apn(void) {
    pid_t pid;
    char numeric[16];
    char buf[256];
    char *argv[40];
    int i, tries;

    if (!cfg_custom_apn_mode || !cfg_apn[0]) return;

    pid = fork();
    if (pid < 0) return;
    if (pid > 0) { waitpid(pid, NULL, 0); return; }   /* parent: reap, carry on */
    if (fork() > 0) _exit(0);                          /* detach: reparent to init */

    /* grandchild: do the slow work off the daemon's input path */
    wait_for_sim();

    snprintf(numeric, sizeof(numeric), "%s%s", cfg_apn_mcc, cfg_apn_mnc);

    i = 0;
    argv[i++] = (char *)"/system/bin/am";
    argv[i++] = (char *)"start";
    /* --user 0 is essential: the daemon runs as pttbridge's app uid (user 0),
     * and am's default target user -2 (current) would require
     * INTERACT_ACROSS_USERS_FULL, which the app uid lacks (SecurityException).
     * Targeting our own user 0 needs no cross-user permission. */
    argv[i++] = (char *)"--user";
    argv[i++] = (char *)"0";
    argv[i++] = (char *)"-f";
    argv[i++] = (char *)"0x20";   /* FLAG_INCLUDE_STOPPED_PACKAGES */
    argv[i++] = (char *)"-n";
    argv[i++] = (char *)"com.porto.apnsetter/.ApnSetterActivity";
    argv[i++] = (char *)"--es"; argv[i++] = (char *)"apn";              argv[i++] = cfg_apn;
    argv[i++] = (char *)"--es"; argv[i++] = (char *)"mcc";              argv[i++] = cfg_apn_mcc;
    argv[i++] = (char *)"--es"; argv[i++] = (char *)"mnc";              argv[i++] = cfg_apn_mnc;
    argv[i++] = (char *)"--es"; argv[i++] = (char *)"numeric";          argv[i++] = numeric;
    argv[i++] = (char *)"--es"; argv[i++] = (char *)"protocol";         argv[i++] = cfg_apn_protocol;
    argv[i++] = (char *)"--es"; argv[i++] = (char *)"roaming_protocol"; argv[i++] = cfg_apn_roaming_protocol;
    argv[i++] = (char *)"--es"; argv[i++] = (char *)"type";             argv[i++] = cfg_apn_type;
    if (cfg_apn_name[0]) { argv[i++] = (char *)"--es"; argv[i++] = (char *)"name"; argv[i++] = cfg_apn_name; }
    argv[i] = NULL;

    /* am can be briefly not-ready right at boot; retry until it dispatches
     * ("Starting: ...") or we give up. --user 0 above is what actually lets the
     * app-uid daemon launch the activity. Bounded; runs in the detached
     * grandchild so it never touches the daemon's own path. */
    for (tries = 0; tries < 6; tries++) {
        int n = exec_read("/system/bin/am", argv, buf, sizeof(buf));
        if (n > 0 && strstr(buf, "Starting")) break;   /* intent dispatched */
        sleep(3);
    }
    fprintf(stderr, "porto-watchdog: custom APN '%s' applied (mcc=%s mnc=%s)\n",
            cfg_apn, cfg_apn_mcc, cfg_apn_mnc);
    _exit(0);
}

int main(int argc, char *argv[]) {
    int btn_fd, knob_fd = -1, ptt_fd_dev = -1, loc_fd = -1;
    struct input_event ev;
    long long last_knob_send = 0;
    long long last_btn_send = 0;
    long long last_loc_send = 0;
    unsigned char pkt[PKT_SIZE];
    struct pollfd fds[5];
    int nfds;
    int config_loaded = 0;

    /* Ignore SIGPIPE: the PTT socket server closes after each read,
     * so writes to a closed socket must return EPIPE, not kill us */
    signal(SIGPIPE, SIG_IGN);

    /* Load config: explicit -f, or auto-detect default path */
    if (argc == 3 && strcmp(argv[1], "-f") == 0) {
        config_loaded = load_config(argv[2]);
        if (!config_loaded) {
            fprintf(stderr, "Cannot open config: %s\n", argv[2]);
            return 1;
        }
    } else if (argc == 1) {
        /* No args: try default config path silently */
        config_loaded = load_config(DEFAULT_CONFIG);
    } else {
        fprintf(stderr,
            "porto-watchdog: TE300K local watchdog daemon\n"
            "Usage:\n"
            "  %s              (auto-loads %s if present)\n"
            "  %s -f <config>  (explicit config path)\n",
            argv[0], DEFAULT_CONFIG, argv[0]);
        return 1;
    }

    /* Check if UDP should be enabled */
    if (config_loaded && cfg_host[0] && cfg_radio_id[0] && cfg_secret[0]) {
        want_udp = 1;
    }

    /* Apply a custom APN if configured (fixes outdated/roaming APNs). Runs on
     * every boot so it survives the firmware re-seeding its default APN. */
    apply_apn();

    /*
     * Boot-resilient startup sequence:
     *   1. Wait for input devices (kernel may not have initialized them yet)
     *   2. Check PTT socket (local)
     *   3. Try DNS once (non-blocking - retries lazily on each keypress)
     */

    /* 1. Open button/PTT device (event3) - retry at boot */
    {
        int retries;
        for (retries = 0; retries < 60; retries++) {
            btn_fd = open(cfg_button_device, O_RDONLY);
            if (btn_fd >= 0) break;
            if (retries == 0)
                fprintf(stderr, "porto-watchdog: waiting for %s ...\n", cfg_button_device);
            sleep(1);
        }
        if (btn_fd < 0) {
            fprintf(stderr, "porto-watchdog: cannot open %s: %s\n",
                    cfg_button_device, strerror(errno));
            return 1;
        }
    }

    /* Open knob device (event4) - optional, also retry briefly */
    {
        int retries;
        for (retries = 0; retries < 10; retries++) {
            knob_fd = open(cfg_device, O_RDONLY);
            if (knob_fd >= 0) break;
            if (retries == 0)
                fprintf(stderr, "porto-watchdog: waiting for %s ...\n", cfg_device);
            sleep(1);
        }
        if (knob_fd < 0)
            fprintf(stderr, "porto-watchdog: knob %s not available (channel switch disabled)\n",
                    cfg_device);
    }

    /* Open RSM PTT device (event2) - optional, retry briefly */
    {
        int retries;
        for (retries = 0; retries < 10; retries++) {
            ptt_fd_dev = open(cfg_ptt_device, O_RDONLY);
            if (ptt_fd_dev >= 0) break;
            if (retries == 0)
                fprintf(stderr, "porto-watchdog: waiting for %s ...\n", cfg_ptt_device);
            sleep(1);
        }
        if (ptt_fd_dev < 0)
            fprintf(stderr, "porto-watchdog: RSM PTT %s not available\n", cfg_ptt_device);
    }

    /* 2. Check PTT socket availability (connect-per-event, no persistent connection) */
    {
        int test_fd = ptt_connect();
        if (test_fd >= 0) {
            close(test_fd);
            printf("porto-watchdog: PTT socket available\n");
        } else {
            fprintf(stderr, "porto-watchdog: PTT socket not ready yet (will connect on keypress)\n");
        }
    }

    /* 3. Try DNS once - if it fails, we'll retry on each keypress (no blocking) */
    if (want_udp) {
        if (!try_resolve_udp()) {
            printf("porto-watchdog: DNS not ready yet, will retry on keypress\n");
            fflush(stdout);
        }
    }

    /* 4. Location socket - only useful when UDP is configured. pttbridge.apk
     * connects here with GPS fixes (and only reads GPS at all when
     * /data/local/tmp/loc.conf exists - see README). */
    if (want_udp) {
        loc_fd = loc_listen();
        if (loc_fd < 0)
            fprintf(stderr, "porto-watchdog: loc socket unavailable (GPS reporting disabled)\n");
    }

    /* Startup banner */
    printf("porto-watchdog: TE300K all-in-one handler\n");
    printf("porto-watchdog: buttons=%s (PTT%s)\n",
           cfg_button_device,
           want_udp ? " emergency ident" : "");
    if (ptt_fd_dev >= 0)
        printf("porto-watchdog: rsm_ptt=%s\n", cfg_ptt_device);
    if (knob_fd >= 0)
        printf("porto-watchdog: knob=%s (channel switch%s)\n",
               cfg_device, want_udp ? "" : " [N/A]");
    if (want_udp)
        printf("porto-watchdog: UDP target=%s:%d radio=%s [%s]\n",
               cfg_host, cfg_port, cfg_radio_id,
               udp_enabled ? "OK" : "waiting for DNS");
    if (loc_fd >= 0)
        printf("porto-watchdog: loc socket=@%s (GPS -> 'L' packets)\n",
               LOC_SOCKET_NAME);
    fflush(stdout);

    /* Set up poll: btn_fd always present, the rest optional. */
    nfds = 0;
    fds[nfds].fd = btn_fd;
    fds[nfds].events = POLLIN;
    nfds++;

    int knob_poll_idx = -1, ptt_poll_idx = -1, loc_poll_idx = -1;
    int udp_poll_idx = -1;
    long long last_heartbeat = 0;

    /* The UDP socket doubles as the receive path for 'C' channel
     * packets - make sure it exists even before DNS resolves. */
    if (want_udp && udp_fd < 0)
        udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd >= 0) {
        udp_poll_idx = nfds;
        fds[nfds].fd = udp_fd;
        fds[nfds].events = POLLIN;
        nfds++;
    }

    if (knob_fd >= 0) {
        knob_poll_idx = nfds;
        fds[nfds].fd = knob_fd;
        fds[nfds].events = POLLIN;
        nfds++;
    }
    if (ptt_fd_dev >= 0) {
        ptt_poll_idx = nfds;
        fds[nfds].fd = ptt_fd_dev;
        fds[nfds].events = POLLIN;
        nfds++;
    }
    if (loc_fd >= 0) {
        loc_poll_idx = nfds;
        fds[nfds].fd = loc_fd;
        fds[nfds].events = POLLIN;
        nfds++;
    }

    /* Main event loop */
    while (1) {
        int ret = poll(fds, nfds, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "poll: %s\n", strerror(errno));
            break;
        }

        /* Minutely heartbeat: fetches a fresh channel name for the
         * idle screen and keeps the NAT return path open so the
         * server's replies reach us on cellular. First pass fires
         * immediately after start. */
        if (want_udp) {
            long long hb_now = now_ms();
            if (hb_now - last_heartbeat >= HEARTBEAT_MS || last_heartbeat == 0) {
                last_heartbeat = hb_now;
                if (!udp_enabled) try_resolve_udp();
                if (udp_enabled) {
                    build_packet(pkt, CMD_HEARTBEAT);
                    if (sendto(udp_fd, pkt, PKT_SIZE, 0,
                               (struct sockaddr *)&udp_dest,
                               sizeof(udp_dest)) < 0)
                        fprintf(stderr, "heartbeat sendto: %s\n",
                                strerror(errno));
                }
            }
        }

        /* Server replies ('C' channel packets) */
        if (udp_poll_idx >= 0 && (fds[udp_poll_idx].revents & POLLIN)) {
            handle_channel_packet();
        }

        if (ret == 0) continue;

        /* Button events: event3 (gpio-keys) */
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(btn_fd, &ev, sizeof(ev));
            if (n < (ssize_t)sizeof(ev)) {
                if (n < 0 && errno == EINTR) continue;
                fprintf(stderr, "Button read error: %s\n", strerror(errno));
                break;
            }

            if (ev.type == EV_KEY) {
                /* PTT: connect-per-event (server closes after each read) */
                if (ev.code == KEY_PTT && (ev.value == 1 || ev.value == 0)) {
                    int ptt_fd = ptt_connect();
                    if (ptt_fd >= 0) {
                        ptt_send(ptt_fd, ev.value);
                        close(ptt_fd);
                        printf("porto-watchdog: PTT %s\n",
                               ev.value ? "DOWN" : "UP");
                        fflush(stdout);
                    } else {
                        fprintf(stderr, "porto-watchdog: PTT socket unavailable\n");
                    }
                }
                /* Emergency & Ident: only on press (value 1) */
                else if (ev.value == 1 && (ev.code == BTN_EMERGENCY || ev.code == BTN_IDENT)) {
                    if (want_udp && !udp_enabled) try_resolve_udp();
                    if (udp_enabled) {
                        if (ev.code == BTN_EMERGENCY)
                            send_udp_command(udp_fd, &udp_dest, pkt, CMD_EMERGENCY,
                                             "EMERGENCY", &last_btn_send);
                        else if (ev.code == BTN_IDENT)
                            send_udp_command(udp_fd, &udp_dest, pkt, CMD_IDENT,
                                             "IDENT", &last_btn_send);
                    }
                }
            }
        }

        /* Knob events: event4 (channel-switch) */
        if (knob_poll_idx >= 0 && (fds[knob_poll_idx].revents & POLLIN)) {
            ssize_t n = read(knob_fd, &ev, sizeof(ev));
            if (n < (ssize_t)sizeof(ev)) {
                if (n < 0 && errno == EINTR) continue;
                fprintf(stderr, "Knob read error: %s\n", strerror(errno));
                break;
            }
            if (ev.type == EV_KEY && ev.value == 1
                    && (ev.code == KNOB_CW || ev.code == KNOB_CCW)) {
                if (want_udp && !udp_enabled) try_resolve_udp();
                if (udp_enabled) {
                    if (ev.code == KNOB_CW)
                        send_udp_command(udp_fd, &udp_dest, pkt, CMD_NEXT,
                                         "NEXT", &last_knob_send);
                    else if (ev.code == KNOB_CCW)
                        send_udp_command(udp_fd, &udp_dest, pkt, CMD_PREV,
                                         "PREV", &last_knob_send);
                }
            }
        }

        /* GPS fixes from pttbridge.apk (abstract socket) */
        if (loc_poll_idx >= 0 && (fds[loc_poll_idx].revents & POLLIN)) {
            handle_loc_client(loc_fd, &last_loc_send);
        }

        /* RSM PTT events: event2 (telo_ptt) */
        if (ptt_poll_idx >= 0 && (fds[ptt_poll_idx].revents & POLLIN)) {
            ssize_t n = read(ptt_fd_dev, &ev, sizeof(ev));
            if (n < (ssize_t)sizeof(ev)) {
                if (n < 0 && errno == EINTR) continue;
                fprintf(stderr, "RSM PTT read error: %s\n", strerror(errno));
                break;
            }
            if (ev.type == EV_KEY && ev.code == KEY_PTT
                    && (ev.value == 1 || ev.value == 0)) {
                int ptt_fd = ptt_connect();
                if (ptt_fd >= 0) {
                    ptt_send(ptt_fd, ev.value);
                    close(ptt_fd);
                    printf("porto-watchdog: RSM PTT %s\n",
                           ev.value ? "DOWN" : "UP");
                    fflush(stdout);
                } else {
                    fprintf(stderr, "porto-watchdog: PTT socket unavailable\n");
                }
            }
        }
    }

    if (udp_fd >= 0) close(udp_fd);
    if (loc_fd >= 0) close(loc_fd);
    if (ptt_fd_dev >= 0) close(ptt_fd_dev);
    if (knob_fd >= 0) close(knob_fd);
    close(btn_fd);
    return 0;
}
