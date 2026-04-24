#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <mosquitto.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mosquitto* mqtt_connect_simple(const char* client_id,
                                      const char* host,
                                      int port,
                                      int keepalive);

int mqtt_loop_start_simple(struct mosquitto* m);
int mqtt_loop_stop_simple(struct mosquitto* m);

int mqtt_sub(struct mosquitto* m, const char* topic);

int mqtt_pub(struct mosquitto* m, const char* topic,
             const void* payload, int len);

void mqtt_disconnect_simple(struct mosquitto* m);

#ifdef __cplusplus
}
#endif

#endif