#include <unistd.h>
void *smalloc(size_t size) { return nullptr; }
void *scalloc(size_t num, size_t size) { return nullptr; }
void sfree(void *p) {}
void *srealloc(void *oldp, size_t size) { return nullptr; }
size_t _num_free_blocks() { return 0; }
size_t _num_free_bytes() { return 0; }
size_t _num_allocated_blocks() { return 0; }
size_t _num_allocated_bytes() { return 0; }
size_t _num_meta_data_bytes() { return 0; }
size_t _size_meta_data() { return 0; }