#include <coap2/coap.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    
    const uint8_t *data_tcp = data;
    if (pdu) {
        coap_set_log_level(LOG_DEBUG);
        coap_pdu_t *pdu_udp = coap_pdu_init(0, 0, 0, size);
        coap_pdu_parse(COAP_PROTO_UDP, data, size, pdu_udp);
        coap_pdu_encode_header(pdu_udp, COAP_PROTO_UDP);
        coap_show_pdu(LOG_DEBUG, pdu_udp);
        coap_delete_pdu(pdu_udp);

        coap_pdu_t *pdu_tcp = coap_pdu_init(0, 0, 0, size);
        coap_pdu_parse(COAP_PROTO_TCP, data_tcp, size, pdu_tcp);
        coap_pdu_encode_header(pdu_udp, COAP_PROTO_TCP);
        coap_show_pdu(LOG_DEBUG, pdu_tcp);
        coap_delete_pdu(pdu_tcp);
    }
    return 0;
}
