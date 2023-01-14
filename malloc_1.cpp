#include <unistd.h>
const int max_size = 100000000;
void *smalloc(size_t size) {
  if (size == 0 || size > max_size) {
    return NULL;
  }
  void *mem_alloced = sbrk(size);
  if (!mem_alloced) {
    return NULL;
  }
  return mem_alloced;
}