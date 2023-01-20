#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

const int max_size = 1e8;
const int mmap_size = 128 * 1024 - sizeof(MetaData);

typedef struct MallocMetadata {
  size_t size;
  bool is_free;
  MallocMetadata *next;
  MallocMetadata *prev;
} MetaData;

class BlockList {
private:
  MetaData *block_list;
  const bool use_mmap;

public:
  BlockList(bool use_mmap) : use_mmap(use_mmap), block_list(nullptr) {}

  static MetaData *getMetaData(void *p);

  void freeBlock(void *ptr);
  void mergeBlocks(MetaData *left, MetaData *right);
  void removeBlock(MetaData *to_remove);
  void insertBlock(MetaData *to_insert);
  void *allocateBlock(size_t size);
  void trySeperate(void *ptr, size_t size);
  void mergeFreeBlocks(void *ptr);
  void expandWilderness(size_t wanted_size);
  MetaData *getWildernessBlock() const;
  MetaData *findLeftBlock(MetaData *block) const;
  MetaData *findRightBlock(MetaData *block) const;

  size_t getNumberOfFreeBlocks() const;
  size_t getNumberOfFreeBytes() const;
  size_t getNumberOfBlocks() const;
  size_t getNumberOfBytes() const;
};

MetaData *BlockList::getMetaData(void *p) {
  MetaData *meta = (MetaData *)((char *)p - sizeof(MetaData));
  return meta;
}

void BlockList::freeBlock(void *ptr) {
  MetaData *to_free = getMetaData(ptr);

  size_t size = to_free->size - sizeof(MetaData);
  assert((use_mmap && size >= mmap_size) || (!use_mmap && size < mmap_size));

  if (use_mmap) {
    removeBlock(to_free);
    munmap(to_free, to_free->size);
  } else {
    to_free->is_free = true;
  }
}

void BlockList::mergeBlocks(MetaData *left, MetaData *right) {
  assert(left < right && (MetaData *)((char *)left + left->size) == right);

  removeBlock(left);
  removeBlock(right);
  left->size += right->size;
  left->next = nullptr;
  left->prev = nullptr;
  insertBlock(left);
}

MetaData *BlockList::getWildernessBlock() const {
  MetaData *wilderness_block = block_list;
  MetaData *itr = block_list;

  while (itr) {
    if (itr > wilderness_block) {
      wilderness_block = itr;
    }
    itr = itr->next;
  }

  return wilderness_block;
}

MetaData *BlockList::findLeftBlock(MetaData *block) const {
  MetaData *itr = block_list;
  while (itr) {
    if ((char *)itr + itr->size == (char *)block) {
      return itr;
    }

    itr = itr->next;
  }

  return nullptr;
}

MetaData *BlockList::findRightBlock(MetaData *block) const {
  MetaData *itr = block_list;
  while (itr) {
    if ((char *)block + block->size == (char *)itr) {
      return itr;
    }
    itr = itr->next;
  }

  return nullptr;
}

void BlockList::trySeperate(void *ptr, size_t size) {
  MetaData *to_seperate = getMetaData(ptr);
  if (to_seperate->size < size + 128 + 2 * sizeof(MetaData)) {
    return;
  }
  removeBlock(to_seperate);

  MetaData *new_block = (MetaData *)((char *)ptr + size);
  new_block->size = to_seperate->size - size - sizeof(MetaData);
  new_block->is_free = true;
  new_block->next = nullptr;
  new_block->prev = nullptr;

  to_seperate->size = size + sizeof(MetaData);

  insertBlock(new_block);
  insertBlock(to_seperate);
}

void BlockList::mergeFreeBlocks(void *ptr) {
  MetaData *block = getMetaData(ptr);
  if (!block->is_free) {
    return;
  }

  MetaData *left = findLeftBlock(block);
  if (left && left->is_free) {
    mergeBlocks(left, block);
    block = left;
  }

  MetaData *right = findRightBlock(block);
  if (right && right->is_free) {
    mergeBlocks(block, right);
  }
}

void BlockList::removeBlock(MetaData *to_remove) {
  if (block_list == to_remove) {
    block_list = to_remove->next;
  }

  if (to_remove->prev != nullptr) {
    to_remove->prev->next = to_remove->next;
  }

  if (to_remove->next != nullptr) {
    to_remove->next->prev = to_remove->prev;
  }
}

void BlockList::insertBlock(MetaData *to_insert) {
  if (block_list == nullptr) {
    block_list = to_insert;
    return;
  }

  MetaData *tail = block_list;
  MetaData *prev = nullptr;

  while ((tail != nullptr) && (to_insert->size > tail->size)) {
    prev = tail;
    tail = tail->next;
  }

  if (tail == nullptr) {
    prev->next = to_insert;
    to_insert->prev = prev;
    return;
  }

  while (tail != nullptr && tail->size == to_insert->size && tail < to_insert) {
    prev = tail;
    tail = tail->next;
  }

  if (prev == nullptr) {
    to_insert->next = tail;
    tail->next = to_insert;
    block_list = to_insert;
    return;
  }

  if (tail == nullptr) {
    prev->next = to_insert;
    to_insert->prev = prev;
    return;
  }

  prev->next = to_insert;
  to_insert->prev = prev;
  to_insert->next = tail;
  tail->prev = to_insert;
}

void *BlockList::allocateBlock(size_t size) {
  assert((use_mmap && size >= mmap_size) || (!use_mmap && size < mmap_size));

  MetaData *new_block;
  size_t alloc_size = size + sizeof(MetaData);

  if (use_mmap) {
    MetaData *meta_data =
        (MetaData *)mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if ((size_t)(meta_data) == (size_t)-1) {
      return nullptr;
    }

    new_block = meta_data;
  } else {
    MetaData *meta_data = block_list;
    while (meta_data != nullptr) {
      if (meta_data->is_free && alloc_size <= meta_data->size) {
        meta_data->is_free = false;
        return (char *)meta_data + sizeof(MetaData);
      }
      meta_data = meta_data->next;
    }

    MetaData *wilderness_block = getWildernessBlock();
    if (wilderness_block->is_free) {
      expandWilderness(alloc_size);
      new_block = wilderness_block;
      removeBlock(wilderness_block);
    } else {
      void *p_break = sbrk(alloc_size);
      if ((size_t)p_break == (size_t)-1) {
        return nullptr;
      }
      new_block = (MetaData *)p_break;
    }
  }

  new_block->size = alloc_size;
  new_block->is_free = false;
  new_block->next = nullptr;
  new_block->prev = nullptr;
  insertBlock(new_block);
  return (char *)new_block + sizeof(MetaData);
}

void BlockList::expandWilderness(size_t wanted_size) {
  MetaData *block = getWildernessBlock();
  if (!block) {
    return;
  }

  removeBlock(block);
  size_t offset = wanted_size - block->size;
  sbrk(offset);
  block->size = wanted_size;
  insertBlock(block);
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

BlockList bl = BlockList(false);
BlockList bl_huge = BlockList(true);

void *smalloc(size_t size) {
  if (size == 0 || size > max_size) {
    return nullptr;
  }

  if (size >= mmap_size) {
    return bl_huge.allocateBlock(size);
  } else {
    void *block = bl.allocateBlock(size);
    bl.trySeperate(block, size);
    return block;
  }
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

  MetaData *meta_data = BlockList::getMetaData(ptr);
  if (meta_data->size >= mmap_size + sizeof(MetaData)) {
    bl_huge.freeBlock(ptr);
  } else {
    bl.freeBlock(ptr);
    bl.mergeFreeBlocks(ptr);
  }
}

void *srealloc(void *oldp, size_t size) {
  if (size == 0 || size > max_size) {
    return nullptr;
  }

  if (oldp == nullptr) {
    return smalloc(size);
  }

  MetaData *old_block = BlockList::getMetaData(oldp);
  size_t old_size = old_block->size;

  if (old_size >= mmap_size + sizeof(MetaData)) {
    if (old_size == size + sizeof(MetaData)) {
      return oldp;
    }

    sfree(oldp);
    return smalloc(size);
  }

  // a
  if (size <= old_size) {
    return oldp;
  }

  void *new_p;

  MetaData *left = bl.findLeftBlock(old_block);
  MetaData *right = bl.findRightBlock(old_block);
  MetaData *wilderness = bl.getWildernessBlock();

  // b
  if (left && right && left->is_free &&
      left->size + old_block->size >= size + sizeof(MetaData)) {
    bl.mergeBlocks(left, old_block);
    left->is_free = false;

    new_p = (char *)left + sizeof(MetaData);
  }

  // c
  else if (!right) {
    if (left && left->is_free) {
      bl.mergeBlocks(left, old_block);
      old_block = left;
    }
    if (old_block->size - sizeof(MetaData) < size) {
      bl.expandWilderness(size + sizeof(MetaData));
    }
    old_block->is_free = false;

    new_p = (char *)left + sizeof(MetaData);
  }

  // d
  else if (right && right->is_free &&
           right->size + old_block->size >= size + sizeof(MetaData)) {
    bl.mergeBlocks(old_block, right);

    new_p = (char *)old_block + sizeof(MetaData);
  }

  // e
  else if (left && right && left->is_free && right->is_free &&
           right->size + left->size + old_block->size >=
               size + sizeof(MetaData)) {
    bl.mergeBlocks(left, old_block);
    bl.mergeBlocks(left, right);
    left->is_free = false;

    new_p = (char *)left + sizeof(MetaData);
  }

  // f
  else if (right == wilderness && right->is_free) {
    if (left && left->is_free) {
      bl.mergeBlocks(left, old_block);
      left->is_free = false;
      old_block = left;
    }

    bl.mergeBlocks(old_block, right);
    bl.expandWilderness(size + sizeof(MetaData));

    new_p = (char *)old_block + sizeof(MetaData);
  }

  else {
    sfree(oldp);
    new_p = smalloc(size);
  }

  if (new_p == NULL) {
    return NULL;
  }

  memcpy(new_p, oldp, old_size);
  return new_p;
}

size_t _num_free_blocks() { return bl.getNumberOfFreeBlocks(); }

size_t _num_free_bytes() { return bl.getNumberOfFreeBytes(); }

size_t _num_allocated_blocks() {
  return bl.getNumberOfBlocks() + bl_huge.getNumberOfBlocks();
}

size_t _num_allocated_bytes() {
  return bl.getNumberOfBytes() + bl_huge.getNumberOfBytes();
}

size_t _num_meta_data_bytes() {
  return (bl.getNumberOfBlocks() + bl_huge.getNumberOfBlocks()) *
         sizeof(MetaData);
}

size_t _size_meta_data() { return sizeof(MetaData); }
