#include <unistd.h>
typedef struct MallocMetadata {
  size_t size;
  bool is_free;
  MallocMetadata *next;
  MallocMetadata *prev;
} MetaData;

class BlockList {
private:
  MetaData *block_list;

public:
  BlockList();
  void insertBlock(MetaData *block);

  size_t getNumberOfFreeBlocks() const;
  size_t getNumberOfFreeBytes() const;
  size_t getNumberOfBlocks() const;
  size_t getNumberOfBytes() const;
};

void *smalloc(size_t size);
void *scalloc(size_t num, size_t size);
void sfree(void *p);
void *srealloc(void *oldp, size_t size);
size_t _num_free_blocks();
size_t _num_free_bytes();
size_t _num_allocated_blocks();
size_t _num_allocated_bytes();
size_t _num_meta_data_bytes();
size_t _size_meta_data() { return sizeof(MetaData); }
