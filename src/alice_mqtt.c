#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>

#include <mosquitto.h>
#include "P434_api.h"
#include "transport.h"
#include "masking.h"

static const char* BROKER_HOST = "192.168.137.8";
static const int   BROKER_PORT = 1883;
static const int   KEEPALIVE   = 30;

static const char* TOPIC_A2B = "sidh/demo/alice2bob";
static const char* TOPIC_B2A = "sidh/demo/bob2alice";

#define SIDH_LEN    CRYPTO_PUBLICKEYBYTES
#define SIDH_SK_LEN CRYPTO_SECRETKEYBYTES

#define NONCE_LEN  16
#define PACKET_LEN (NONCE_LEN + SIDH_LEN)

/* Bootstrap shared static seed */
static const uint8_t BOOTSTRAP_SEED[] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x0A
};
#define BOOTSTRAP_SEED_LEN (sizeof(BOOTSTRAP_SEED))

/* --- Sync --- */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv = PTHREAD_COND_INITIALIZER;

/* --- State --- */
static uint8_t g_bob_nonce[NONCE_LEN];
static uint8_t g_bob_masked_sidh[SIDH_LEN];
static int g_have_bob_payload = 0;

static void die(const char* where) {
    fprintf(stderr, "[ERR] %s failed\n", where);
    exit(EXIT_FAILURE);
}

static void fill_nonce(uint8_t *nonce, size_t len) {
    for (size_t i = 0; i < len; i++) {
        nonce[i] = (uint8_t)(rand() & 0xFF);
    }
}

/* --- MQTT callback --- */
static void on_message(struct mosquitto* m, void* userdata,
                       const struct mosquitto_message* msg) {
    (void)m;
    (void)userdata;

    pthread_mutex_lock(&g_mu);

    if (strcmp(msg->topic, TOPIC_B2A) == 0) {
        if (msg->payloadlen == PACKET_LEN) {
            const uint8_t* p = (const uint8_t*)msg->payload;
            memcpy(g_bob_nonce, p, NONCE_LEN);
            memcpy(g_bob_masked_sidh, p + NONCE_LEN, SIDH_LEN);
            g_have_bob_payload = 1;

            fprintf(stdout,
                    "[Alice] Received Bob payload (nonce + masked SIDH = %d bytes)\n",
                    msg->payloadlen);

            pthread_cond_broadcast(&g_cv);
        } else {
            fprintf(stderr,
                    "[Alice] Unexpected B2A payload size: %d (expected %d)\n",
                    msg->payloadlen, PACKET_LEN);
        }
    }

    pthread_mutex_unlock(&g_mu);
}

int main(void) {
    srand((unsigned)time(NULL));

    /* 1) MQTT */
    struct mosquitto* mq = mqtt_connect_simple("alice", BROKER_HOST, BROKER_PORT, KEEPALIVE);
    if (!mq) {
        return 1;
    }

    mosquitto_message_callback_set(mq, on_message);
    if (mqtt_loop_start_simple(mq) != MOSQ_ERR_SUCCESS) {
        die("mqtt_loop_start_simple");
    }

    if (mqtt_sub(mq, TOPIC_B2A) != MOSQ_ERR_SUCCESS) {
        die("mqtt_sub(TOPIC_B2A)");
    }

    /* 2) Generate Alice SIDH/SIKE p434 keypair */
    uint8_t alice_sidh_pub[SIDH_LEN];
    uint8_t alice_sidh_sk[SIDH_SK_LEN];

    if (crypto_kem_keypair_SIKEp434(alice_sidh_pub, alice_sidh_sk) != 0) {
        die("crypto_kem_keypair_SIKEp434");
    }

    /* Optional copy for verification */
    uint8_t alice_sidh_copy[SIDH_LEN];
    memcpy(alice_sidh_copy, alice_sidh_pub, SIDH_LEN);

    /* 3) Generate nonce */
    uint8_t nonce[NONCE_LEN];
    fill_nonce(nonce, sizeof(nonce));

    /* 4) Mask with static seed + SHAKE256 */
    if (!mask_bytes_with_seed_shake256_ex(
            BOOTSTRAP_SEED, BOOTSTRAP_SEED_LEN,
            nonce, sizeof(nonce),
            "sidh-mask|A2B|v1",
            alice_sidh_pub, SIDH_LEN)) {
        die("mask_bytes_with_seed_shake256_ex(Alice mask)");
    }

    /* 5) Send nonce || masked SIDH public key */
    uint8_t pkt[PACKET_LEN];
    memcpy(pkt, nonce, NONCE_LEN);
    memcpy(pkt + NONCE_LEN, alice_sidh_pub, SIDH_LEN);

    if (mqtt_pub(mq, TOPIC_A2B, pkt, (int)sizeof(pkt)) != MOSQ_ERR_SUCCESS) {
        die("mqtt_pub(TOPIC_A2B)");
    }

    fprintf(stdout, "[Alice] Sent nonce + masked SIDH (%zu bytes) -> %s\n",
            sizeof(pkt), TOPIC_A2B);

    /* 6) Wait for Bob payload */
    pthread_mutex_lock(&g_mu);
    while (!g_have_bob_payload) {
        pthread_cond_wait(&g_cv, &g_mu);
    }
    pthread_mutex_unlock(&g_mu);

    /* 7) Unmask Bob SIDH public key */
    uint8_t bob_sidh_unmasked[SIDH_LEN];
    memcpy(bob_sidh_unmasked, g_bob_masked_sidh, SIDH_LEN);

    if (!mask_bytes_with_seed_shake256_ex(
            BOOTSTRAP_SEED, BOOTSTRAP_SEED_LEN,
            g_bob_nonce, NONCE_LEN,
            "sidh-mask|B2A|v1",
            bob_sidh_unmasked, SIDH_LEN)) {
        die("mask_bytes_with_seed_shake256_ex(Alice unmask)");
    }

    /* 8) Optional round-trip check */
    uint8_t tmp[SIDH_LEN];
    memcpy(tmp, bob_sidh_unmasked, SIDH_LEN);

    if (!mask_bytes_with_seed_shake256_ex(
            BOOTSTRAP_SEED, BOOTSTRAP_SEED_LEN,
            g_bob_nonce, NONCE_LEN,
            "sidh-mask|B2A|v1",
            tmp, SIDH_LEN)) {
        die("mask_bytes_with_seed_shake256_ex(Alice remask)");
    }

    if (memcmp(tmp, g_bob_masked_sidh, SIDH_LEN) == 0) {
        printf("[Alice][OK] Bob unmask/remask is consistent.\n");
    } else {
        printf("[Alice][WARN] Remask != received payload.\n");
    }

    /* Cleanup */
    memset(alice_sidh_sk, 0, sizeof(alice_sidh_sk));
    memset(alice_sidh_copy, 0, sizeof(alice_sidh_copy));
    memset(bob_sidh_unmasked, 0, sizeof(bob_sidh_unmasked));
    memset(tmp, 0, sizeof(tmp));

    mqtt_loop_stop_simple(mq);
    mqtt_disconnect_simple(mq);

    return 0;
}