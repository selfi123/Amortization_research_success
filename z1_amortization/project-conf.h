/**
 * project-conf.h
 * Contiki-NG Configuration - *** Z1 MOTE VARIANT ***
 * Zolertia Z1 (MSP430F2617): 8KB RAM, 92KB Flash
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Network Configuration */
#define UDP_PORT 5678
#define NETSTACK_CONF_WITH_IPV6 1

/* Z1 Stack Size - Reduced from 4096 to 1024 to fit in 8KB RAM.
 * Polynomial operations use local stack variables (~512B).
 * 1024 gives comfortable headroom without exhausting heap. */
#ifndef PROCESS_CONF_STACKSIZE
#define PROCESS_CONF_STACKSIZE 1024
#endif

/* UDP/IP Buffer Size - Reduced from 1280 to 140 bytes (just above MTU=127) */
#define UIP_CONF_BUFFER_SIZE 140

/* Enable printf support for debugging */
#define LOG_CONF_LEVEL_IPV6 LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_MAIN LOG_LEVEL_INFO

/* Memory optimization for 8KB RAM */
#define NBR_TABLE_CONF_MAX_NEIGHBORS 2
#define UIP_CONF_MAX_ROUTES 2

/* Crypto work buffer - reduced for Z1 */
#define CRYPTO_WORK_BUFFER_SIZE 512

/* Enable UDP support */
#define UIP_CONF_UDP 1

/* Disable RPL DAG MC (Metric Container) to save memory */
#define RPL_CONF_WITH_MC 0

/* Disable unnecessary features to save RAM */
#define SICSLOWPAN_CONF_FRAG 1
#define QUEUEBUF_CONF_NUM 4

#endif /* PROJECT_CONF_H_ */
