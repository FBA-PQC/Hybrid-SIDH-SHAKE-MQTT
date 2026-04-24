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
#define NONCE_LEN   16
#define PACKET_LEN  (NONCE_LEN + SIDH_LEN)

/* SAME bootstrap seed as Alice */
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
static uint8_t g_alice_nonce[NONCE_LEN];
static uint8_t g_alice_masked_sidh[SIDH_LEN];
static int g_have_alice_payload = 0;

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

    if (strcmp(msg->topic, TOPIC_A2B) == 0) {
        if (msg->payloadlen == PACKET_LEN) {
            const uint8_t* p = (const uint8_t*)msg->payload;

            memcpy(g_alice_nonce, p, NONCE_LEN);
            memcpy(g_alice_masked_sidh, p + NONCE_LEN, SIDH_LEN);

            g_have_alice_payload = 1;

            fprintf(stdout, "[Bob] Received Alice payload (%d bytes)\n",
                    msg->payloadlen);

            pthread_cond_broadcast(&g_cv);
        } else {
            fprintf(stderr, "[Bob] Unexpected A2B payload size: %d (expected %d)\n",
                    msg->payloadlen, PACKET_LEN);
        }
    }

    pthread_mutex_unlock(&g_mu);
}

int main(void) {
    srand((unsigned)time(NULL));

    /* 1) MQTT */
    struct mosquitto* mq = mqtt_connect_simple("bob", BROKER_HOST, BROKER_PORT, KEEPALIVE);
    if (!mq) {
        return 1;
    }

    mosquitto_message_callback_set(mq, on_message);

    if (mqtt_loop_start_simple(mq) != MOSQ_ERR_SUCCESS) {
        die("mqtt_loop_start_simple");
    }

    if (mqtt_sub(mq, TOPIC_A2B) != MOSQ_ERR_SUCCESS) {
        die("mqtt_sub(TOPIC_A2B)");
    }

    /* 2) Wait for Alice payload */
    pthread_mutex_lock(&g_mu);
    while (!g_have_alice_payload) {
        pthread_cond_wait(&g_cv, &g_mu);
    }
    pthread_mutex_unlock(&g_mu);

    /* 3) Unmask Alice SIDH public key */
    uint8_t alice_sidh_unmasked[SIDH_LEN];
    memcpy(alice_sidh_unmasked, g_alice_masked_sidh, SIDH_LEN);

    if (!mask_bytes_with_seed_shake256_ex(
            BOOTSTRAP_SEED, BOOTSTRAP_SEED_LEN,
            g_alice_nonce, NONCE_LEN,
            "sidh-mask|A2B|v1",
            alice_sidh_unmasked, SIDH_LEN)) {
        die("mask_bytes_with_seed_shake256_ex(Bob unmask Alice)");
    }

    printf("[Bob] Alice SIDH public key recovered\n");

    /* 4) Generate Bob SIDH keypair */
    uint8_t bob_sidh_pub[SIDH_LEN];
    uint8_t bob_sidh_sk[SIDH_SK_LEN];

    if (crypto_kem_keypair_SIKEp434(bob_sidh_pub, bob_sidh_sk) != 0) {
        die("crypto_kem_keypair_SIKEp434");
    }

    uint8_t bob_copy[SIDH_LEN];
    memcpy(bob_copy, bob_sidh_pub, SIDH_LEN);

    /* 5) Generate nonce */
    uint8_t nonce[NONCE_LEN];
    fill_nonce(nonce, sizeof(nonce));

    /* 6) Mask Bob SIDH public key */
    if (!mask_bytes_with_seed_shake256_ex(
            BOOTSTRAP_SEED, BOOTSTRAP_SEED_LEN,
            nonce, NONCE_LEN,
            "sidh-mask|B2A|v1",
            bob_sidh_pub, SIDH_LEN)) {
        die("mask_bytes_with_seed_shake256_ex(Bob mask)");
    }

    /* 7) Send nonce || masked SIDH */
    uint8_t pkt[PACKET_LEN];
    memcpy(pkt, nonce, NONCE_LEN);
    memcpy(pkt + NONCE_LEN, bob_sidh_pub, SIDH_LEN);

    if (mqtt_pub(mq, TOPIC_B2A, pkt, (int)sizeof(pkt)) != MOSQ_ERR_SUCCESS) {
        die("mqtt_pub(TOPIC_B2A)");
    }

    printf("[Bob] Sent nonce + masked SIDH (%d bytes)\n", (int)sizeof(pkt));

    /* 8) Verification (optional) */
    uint8_t check[SIDH_LEN];
    memcpy(check, bob_copy, SIDH_LEN);

    if (!mask_bytes_with_seed_shake256_ex(
            BOOTSTRAP_SEED, BOOTSTRAP_SEED_LEN,
            nonce, NONCE_LEN,
            "sidh-mask|B2A|v1",
            check, SIDH_LEN)) {
        die("mask_bytes_with_seed_shake256_ex(Bob remask check)");
    }

    if (memcmp(check, pkt + NONCE_LEN, SIDH_LEN) == 0) {
        printf("[Bob][OK] Masking is consistent\n");
    } else {
        printf("[Bob][FAIL] Mask mismatch\n");
    }

    /* Cleanup */
    memset(bob_sidh_sk, 0, sizeof(bob_sidh_sk));
    memset(bob_copy, 0, sizeof(bob_copy));
    memset(alice_sidh_unmasked, 0, sizeof(alice_sidh_unmasked));
    memset(check, 0, sizeof(check));

    mqtt_loop_stop_simple(mq);
    mqtt_disconnect_simple(mq);

    return 0;
}