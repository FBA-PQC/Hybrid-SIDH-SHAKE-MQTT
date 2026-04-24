// transport_mqtt.c
#define _GNU_SOURCE
#include "transport_mqtt.h"
#include <mosquitto.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct mqtt_client {
    struct mosquitto* m;
    char* topic_sub;
    char* topic_pub;

    pthread_mutex_t mu;
    pthread_cond_t  cv;

    int have_ack;
    ack_t last_ack;
};

static void on_message_cb(struct mosquitto* m, void* userdata,
                          const struct mosquitto_message* msg)
{
    (void)m;
    struct mqtt_client* c = (struct mqtt_client*)userdata;
    if(!c || !msg || !msg->payload) return;
    if((size_t)msg->payloadlen < sizeof(ack_t)) return;

    ack_t a;
    memcpy(&a, msg->payload, sizeof(a)); // endian local (OK si mêmes archis)
    pthread_mutex_lock(&c->mu);
    c->last_ack = a;
    c->have_ack = 1;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

struct mqtt_client* mqtt_connect_simple(const char* client_id,
                                        const char* host, int port,
                                        const char* topic_sub,
                                        const char* topic_pub)
{
    mosquitto_lib_init();
    struct mqtt_client* c = calloc(1, sizeof(*c));
    if(!c) return NULL;

    c->m = mosquitto_new(client_id, true, c);
    if(!c->m){ free(c); return NULL; }

    mosquitto_message_callback_set(c->m, on_message_cb);

    if(mosquitto_connect(c->m, host, port, 30) != MOSQ_ERR_SUCCESS){
        fprintf(stderr, "[MQTT] connect %s:%d failed\n", host, port);
        mosquitto_destroy(c->m); free(c); return NULL;
    }
    if(topic_sub){
        if(mosquitto_subscribe(c->m, NULL, topic_sub, 1) != MOSQ_ERR_SUCCESS){
            fprintf(stderr, "[MQTT] subscribe %s failed\n", topic_sub);
            mosquitto_disconnect(c->m);
            mosquitto_destroy(c->m); free(c); return NULL;
        }
        c->topic_sub = strdup(topic_sub);
    }
    if(topic_pub) c->topic_pub = strdup(topic_pub);

    pthread_mutex_init(&c->mu, NULL);
    pthread_cond_init(&c->cv, NULL);
    c->have_ack = 0;

    if(mosquitto_loop_start(c->m) != MOSQ_ERR_SUCCESS){
        fprintf(stderr, "[MQTT] loop_start failed\n");
        mosquitto_disconnect(c->m);
        mosquitto_destroy(c->m); free(c); return NULL;
    }
    return c;
}

void mqtt_disconnect_simple(struct mqtt_client* c){
    if(!c) return;
    mosquitto_loop_stop(c->m, true);
    mosquitto_disconnect(c->m);
    mosquitto_destroy(c->m);
    free(c->topic_sub);
    free(c->topic_pub);
    pthread_mutex_destroy(&c->mu);
    pthread_cond_destroy(&c->cv);
    free(c);
    mosquitto_lib_cleanup();
}

int mqtt_tx_roundtrip(struct mqtt_client* c,
                      const uint8_t* payload, size_t len,
                      uint32_t seq, int ack_timeout_ms,
                      ack_t* ack_out)
{
    if(!c || !c->m || !c->topic_pub || !c->topic_sub) return -1;

    // construire [seq||payload]
    size_t out_len = sizeof(uint32_t) + len;
    uint8_t* out = (uint8_t*)malloc(out_len);
    if(!out) return -2;
    memcpy(out, &seq, sizeof(uint32_t));
    memcpy(out+sizeof(uint32_t), payload, len);

    // reset état ack
    pthread_mutex_lock(&c->mu);
    c->have_ack = 0;
    pthread_mutex_unlock(&c->mu);

    int rc = mosquitto_publish(c->m, NULL, c->topic_pub, (int)out_len, out, 1, false);
    free(out);
    if(rc != MOSQ_ERR_SUCCESS){
        fprintf(stderr, "[MQTT] publish rc=%d\n", rc);
        return -3;
    }

    // attendre ACK
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ack_timeout_ms / 1000;
    ts.tv_nsec += (ack_timeout_ms % 1000) * 1000000L;
    if(ts.tv_nsec >= 1000000000L){ ts.tv_sec++; ts.tv_nsec -= 1000000000L; }

    int ok = 0;
    pthread_mutex_lock(&c->mu);
    while(!c->have_ack){
        int e = pthread_cond_timedwait(&c->cv, &c->mu, &ts);
        if(e) break;
    }
    if(c->have_ack && c->last_ack.seq == seq){
        ok = 1;
        if(ack_out) *ack_out = c->last_ack;
    }
    pthread_mutex_unlock(&c->mu);

    return ok ? 0 : -4; // timeout / mauvais seq
}
