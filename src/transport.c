#include "transport.h"
#include <stdio.h>
#include <string.h>
#include <mosquitto.h>

struct mosquitto* mqtt_connect_simple(const char* client_id,
                                      const char* host, int port, int keepalive)
{
    mosquitto_lib_init();

    struct mosquitto* m = mosquitto_new(client_id, true, NULL);
    if(!m){
        fprintf(stderr, "[ERR] mosquitto_new\n");
        return NULL;
    }

    if(mosquitto_connect(m, host, port, keepalive) != MOSQ_ERR_SUCCESS){
        fprintf(stderr, "[ERR] mosquitto_connect to %s:%d\n", host, port);
        mosquitto_destroy(m);
        return NULL;
    }

    return m;
}

int mqtt_loop_start_simple(struct mosquitto* m){
    if(!m) return MOSQ_ERR_INVAL;
    return mosquitto_loop_start(m);
}

int mqtt_loop_stop_simple(struct mosquitto* m){
    if(!m) return MOSQ_ERR_INVAL;
    return mosquitto_loop_stop(m, true);
}

int mqtt_sub(struct mosquitto* m, const char* topic){
    if(!m || !topic) return MOSQ_ERR_INVAL;

    int rc = mosquitto_subscribe(m, NULL, topic, 0);
    if(rc != MOSQ_ERR_SUCCESS){
        fprintf(stderr, "[ERR] subscribe %s (%d)\n", topic, rc);
    }
    return rc;
}

int mqtt_pub(struct mosquitto* m, const char* topic, const void* payload, int len){
    if(!m || !topic || (!payload && len > 0) || len < 0) return MOSQ_ERR_INVAL;

    int rc = mosquitto_publish(m, NULL, topic, len, payload, 0, false);
    if(rc != MOSQ_ERR_SUCCESS){
        fprintf(stderr, "[ERR] publish %s (%d)\n", topic, rc);
    }
    return rc;
}

void mqtt_disconnect_simple(struct mosquitto* m){
    if(m){
        mosquitto_disconnect(m);
        mosquitto_destroy(m);
    }
    mosquitto_lib_cleanup();
}