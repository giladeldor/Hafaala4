#include <string.h>
#include <unistd.h>

const int max_size = 1e8;

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
  MetaData *meta = (MetaData *)((char *)p - sizeof(MetaData));
  return meta;
}

void BlockList::freeBlock(void *ptr) {
  MetaData *to_free = getMetaData(ptr);
  to_free->is_free = true;
}
void BlockList::insertBlock(MetaData *to_insert) {
  if (block_list == nullptr) {
    block_list = to_insert;
    return;
  }

  MetaData *tail = block_list;
  while (tail->next != nullptr) {
    tail = tail->next;
  }

  tail->next = to_insert;
  to_insert->prev = tail;
}

void *BlockList::allocateBlock(size_t size) {
  MetaData *meta_data = block_list;
  size_t alloc_size = size + sizeof(MetaData);
  while (meta_data != nullptr) {
    if (meta_data->is_free && alloc_size <= meta_data->size) {
      meta_data->is_free = false;
      return (char *)meta_data + sizeof(MetaData);
    }
    meta_data = meta_data->next;
  }

  void *p_break = sbrk(alloc_size);
  if ((size_t)p_break == (size_t)-1) {
    return nullptr;
  }

  MetaData *new_block = (MetaData *)p_break;
  new_block->size = alloc_size;
  new_block->is_free = false;
  new_block->next = nullptr;
  new_block->prev = nullptr;
  insertBlock(new_block);
  return (char *)p_break + sizeof(MetaData);
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
    count += temp->size - sizeof(MetaData);
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
      count += temp->size - sizeof(MetaData);
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

  return bl.allocateBlock(size);
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

  void *new_p = smalloc(size);
  if (new_p == NULL) {
    return NULL;
  }

  memcpy(new_p, oldp, old_size);
  sfree(oldp);
  return new_p;
}

size_t _num_free_blocks() { return bl.getNumberOfFreeBlocks(); }

size_t _num_free_bytes() { return bl.getNumberOfFreeBytes(); }

size_t _num_allocated_blocks() { return bl.getNumberOfBlocks(); }

size_t _num_allocated_bytes() { return bl.getNumberOfBytes(); }

size_t _num_meta_data_bytes() {
  return bl.getNumberOfBlocks() * sizeof(MetaData);
}

size_t _size_meta_data() { return sizeof(MetaData); }
