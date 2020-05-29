#include <coap2/coap.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    coap_uri_t *uri;
    coap_split_uri(data, size, uri);
    coap_clone_uri(uri);
    return 0;
}
