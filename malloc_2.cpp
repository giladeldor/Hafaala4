#include <string.h>
#include <unistd.h>

const int max_size = 100000000;

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
  BlockList() { block_list = nullptr; }

  MetaData *getMetaData(void *p) const;

  void freeBlock(void *ptr);
  void insertBlock(MetaData *to_insert);
  void *allocateBlock(size_t size);

  size_t getNumberOfFreeBlocks() const;
  size_t getNumberOfFreeBytes() const;
  size_t getNumberOfBlocks() const;
  size_t getNumberOfBytes() const;
};

MetaData *BlockList::getMetaData(void *p) const {
  // return (MetaData *)(block_list->next - p);
  return block_list;
}

void BlockList::freeBlock(void *ptr) {
  MetaData *to_free = getMetaData(ptr);
  to_free->is_free = true;
}
void BlockList::insertBlock(MetaData *to_insert) {
  MetaData *tail = block_list;
  MetaData *prev = NULL;
  while (tail != nullptr) {
    prev = tail;
    tail = tail->next;
  }
  if (prev == nullptr) {
    block_list = to_insert;
  } else {
    prev->next = to_insert;
    to_insert->prev = prev;
  }
}

void *BlockList::allocateBlock(size_t size) {
  MetaData *meta_data = block_list;
  size_t alloc_size = size + sizeof(MetaData);
  while (meta_data != nullptr) {
    if (meta_data->is_free && size <= meta_data->size) {
      meta_data->is_free = false;
      return meta_data;
    }
    meta_data = meta_data->next;
  }
  void *allocate_block = sbrk(alloc_size);
  if (allocate_block == (void *)-1) {
    return nullptr;
  }

  MetaData *new_block = (MetaData *)allocate_block;
  new_block->size = alloc_size;
  new_block->is_free = false;
  new_block->next = nullptr;
  new_block->prev = nullptr;
  insertBlock(new_block);
  return allocate_block;
}

size_t BlockList::getNumberOfBlocks() const {
  MetaData *temp = block_list;
  size_t count = 0;
  while (temp != nullptr) {
    count++;
    temp = temp->next;
  }
  return count;
}

size_t BlockList::getNumberOfBytes() const {
  MetaData *temp = block_list;
  size_t count = 0;
  while (temp != nullptr) {
    count += temp->size;
    temp = temp->next;
  }
  return count;
}

size_t BlockList::getNumberOfFreeBlocks() const {
  MetaData *temp = block_list;
  size_t count = 0;
  while (temp != nullptr) {
    if (temp->is_free) {
      count++;
    }
    temp = temp->next;
  }
  return count;
}

size_t BlockList::getNumberOfFreeBytes() const {
  MetaData *temp = block_list;
  size_t count = 0;
  while (temp != nullptr) {
    if (temp->is_free) {
      count += temp->size;
    }
    temp = temp->next;
  }
  return count;
}

BlockList bl = BlockList();
void *smalloc(size_t size) {
  if (size == 0 || size > max_size) {
    return nullptr;
  }
  void *allocated_block = bl.allocateBlock(size);
  if (allocated_block == nullptr) {
    return nullptr;
  }
  // return allocated_block + sizeof(MetaData);
  return (char *)allocated_block + sizeof(MetaData);
}

void *scalloc(size_t num, size_t size) {
  void *ptr = smalloc(num * size);
  if (ptr == NULL) {
    return NULL;
  }
  memset(ptr, 0, num * size);
  return ptr;
}

void sfree(void *ptr) {
  if (ptr == nullptr) {
    return;
  }
  bl.freeBlock(ptr);
}
void *srealloc(void *oldp, size_t size) {
  if (size == 0 || size > max_size) {
    return nullptr;
  }
  if (oldp == nullptr) {
    return smalloc(size);
  }
  MetaData *old_block = bl.getMetaData(oldp);
  size_t old_size = old_block->size;
  if (size <= old_size) {
    return oldp;
  }

  void *new_block = smalloc(size);
  if (new_block == NULL) {
    return NULL;
  }
  memcpy(new_block, oldp, old_size);
  sfree(oldp);
  return new_block;
}

size_t _num_free_blocks() { return bl.getNumberOfFreeBlocks(); }

size_t _num_free_bytes() { return bl.getNumberOfFreeBytes(); }

size_t _num_allocated_blocks() { return bl.getNumberOfBlocks(); }

size_t _num_allocated_bytes() { return bl.getNumberOfBytes(); }

size_t _num_meta_data_bytes() {
  return bl.getNumberOfBytes() * sizeof(MetaData);
}

size_t _size_meta_data() { return sizeof(MetaData); }
