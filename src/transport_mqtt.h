// transport_mqtt.h
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mqtt_client;

// ACK renvoyé par Bob: seq (écho) + durée locale d'unmask en microsecondes
typedef struct {
    uint32_t seq;
    uint64_t t_unmask_us;
} ack_t;

// Connexion simple + abonnement/publication (QoS=1)
struct mqtt_client* mqtt_connect_simple(const char* client_id,
                                        const char* host, int port,
                                        const char* topic_sub, // où on reçoit l'ACK
                                        const char* topic_pub  // où on publie nos paquets
                                        );

void mqtt_disconnect_simple(struct mqtt_client* c);

// Publication [seq||payload] + attente ACK {seq, t_unmask_us}
// Retour 0 si OK, !=0 si timeout/erreur. Remplit *ack_out si non-NULL.
int mqtt_tx_roundtrip(struct mqtt_client* c,
                      const uint8_t* payload, size_t len,
                      uint32_t seq, int ack_timeout_ms,
                      ack_t* ack_out);

#ifdef __cplusplus
}
#endif
