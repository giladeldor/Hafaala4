#include <unistd.h>
const int max_size = 1e8;
void *smalloc(size_t size) {
  if (size == 0 || size > max_size) {
    return NULL;
  }
  void *p_break = sbrk(size);
  if ((size_t)p_break == (size_t)-1) {
    return NULL;
  }
  return p_break;
}