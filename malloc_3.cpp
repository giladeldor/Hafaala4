#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef __int32_t int32_t;

static int32_t getCookie() {
  static int32_t cookie = rand();
  return cookie;
}

#define PROP(type, name)                                                       \
  type get_##name() const {                                                    \
    checkCookie();                                                             \
    return name;                                                               \
  }                                                                            \
  void set_##name(type val) {                                                  \
    checkCookie();                                                             \
    name = val;                                                                \
  }

struct MetaData {
  PROP(size_t, size);
  PROP(bool, is_free);
  PROP(MetaData *, next);
  PROP(MetaData *, prev);

  void initCookie() { cookie = getCookie(); }

private:
  void checkCookie() const {
    if (cookie != getCookie()) {
      exit(0xDEADBEEF);
    }
  }

private:
  int32_t cookie;
  size_t size;
  bool is_free;
  MetaData *next;
  MetaData *prev;
};

const int max_size = 1e8;
const int mmap_size = 128 * 1024 - sizeof(MetaData);

class BlockList {
private:
  MetaData *block_list;
  const bool use_mmap;

public:
  BlockList(bool use_mmap) : block_list(nullptr), use_mmap(use_mmap) {}

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

  size_t size = to_free->get_size() - sizeof(MetaData);
  assert((use_mmap && size >= mmap_size) || (!use_mmap && size < mmap_size));

  if (use_mmap) {
    removeBlock(to_free);
    munmap(to_free, to_free->get_size());
  } else {
    to_free->set_is_free(true);
  }
}

void BlockList::mergeBlocks(MetaData *left, MetaData *right) {
  assert(left < right &&
         (MetaData *)((char *)left + left->get_size()) == right);

  removeBlock(left);
  removeBlock(right);
  left->set_size(left->get_size() + right->get_size());
  left->set_next(nullptr);
  left->set_prev(nullptr);
  insertBlock(left);
}

MetaData *BlockList::getWildernessBlock() const {
  MetaData *wilderness_block = block_list;
  MetaData *itr = block_list;

  while (itr) {
    if (itr > wilderness_block) {
      wilderness_block = itr;
    }
    itr = itr->get_next();
  }

  return wilderness_block;
}

MetaData *BlockList::findLeftBlock(MetaData *block) const {
  MetaData *itr = block_list;
  while (itr) {
    if ((char *)itr + itr->get_size() == (char *)block) {
      return itr;
    }

    itr = itr->get_next();
  }

  return nullptr;
}

MetaData *BlockList::findRightBlock(MetaData *block) const {
  MetaData *itr = block_list;
  while (itr) {
    if ((char *)block + block->get_size() == (char *)itr) {
      return itr;
    }
    itr = itr->get_next();
  }

  return nullptr;
}

void BlockList::trySeperate(void *ptr, size_t size) {
  MetaData *to_seperate = getMetaData(ptr);
  if (to_seperate->get_size() < size + 128 + 2 * sizeof(MetaData)) {
    return;
  }
  removeBlock(to_seperate);

  MetaData *new_block = (MetaData *)((char *)ptr + size);
  new_block->initCookie();
  new_block->set_size(to_seperate->get_size() - size - sizeof(MetaData));
  new_block->set_is_free(true);
  new_block->set_next(nullptr);
  new_block->set_prev(nullptr);

  to_seperate->set_size(size + sizeof(MetaData));

  insertBlock(new_block);
  insertBlock(to_seperate);
}

void BlockList::mergeFreeBlocks(void *ptr) {
  MetaData *block = getMetaData(ptr);
  if (!block->get_is_free()) {
    return;
  }

  MetaData *left = findLeftBlock(block);
  if (left && left->get_is_free()) {
    mergeBlocks(left, block);
    block = left;
  }

  MetaData *right = findRightBlock(block);
  if (right && right->get_is_free()) {
    mergeBlocks(block, right);
  }
}

void BlockList::removeBlock(MetaData *to_remove) {
  if (block_list == to_remove) {
    block_list = to_remove->get_next();
  }

  if (to_remove->get_prev() != nullptr) {
    to_remove->get_prev()->set_next(to_remove->get_next());
  }

  if (to_remove->get_next() != nullptr) {
    to_remove->get_next()->set_prev(to_remove->get_prev());
  }
}

void BlockList::insertBlock(MetaData *to_insert) {
  if (block_list == nullptr) {
    block_list = to_insert;
    return;
  }

  MetaData *tail = block_list;
  MetaData *prev = nullptr;

  while ((tail != nullptr) && (to_insert->get_size() > tail->get_size())) {
    prev = tail;
    tail = tail->get_next();
  }

  if (tail == nullptr) {
    prev->set_next(to_insert);
    to_insert->set_prev(prev);
    return;
  }

  while (tail != nullptr && tail->get_size() == to_insert->get_size() &&
         tail < to_insert) {
    prev = tail;
    tail = tail->get_next();
  }

  if (prev == nullptr) {
    to_insert->set_next(tail);
    tail->set_next(to_insert);
    block_list = to_insert;
    return;
  }

  if (tail == nullptr) {
    prev->set_next(to_insert);
    to_insert->set_prev(prev);
    return;
  }

  prev->set_next(to_insert);
  to_insert->set_prev(prev);
  to_insert->set_next(tail);
  tail->set_prev(to_insert);
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
      if (meta_data->get_is_free() && alloc_size <= meta_data->get_size()) {
        meta_data->set_is_free(false);
        return (char *)meta_data + sizeof(MetaData);
      }
      meta_data = meta_data->get_next();
    }

    MetaData *wilderness_block = getWildernessBlock();
    if (wilderness_block && wilderness_block->get_is_free()) {
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

  new_block->initCookie();
  new_block->set_size(alloc_size);
  new_block->set_is_free(false);
  new_block->set_next(nullptr);
  new_block->set_prev(nullptr);
  insertBlock(new_block);
  return (char *)new_block + sizeof(MetaData);
}

void BlockList::expandWilderness(size_t wanted_size) {
  MetaData *block = getWildernessBlock();
  if (!block) {
    return;
  }

  removeBlock(block);
  size_t offset = wanted_size - block->get_size();
  sbrk(offset);
  block->set_size(wanted_size);
  insertBlock(block);
}

size_t BlockList::getNumberOfBlocks() const {
  MetaData *temp = block_list;
  size_t count = 0;
  while (temp != nullptr) {
    count++;
    temp = temp->get_next();
  }
  return count;
}

size_t BlockList::getNumberOfBytes() const {
  MetaData *temp = block_list;
  size_t count = 0;
  while (temp != nullptr) {
    count += temp->get_size() - sizeof(MetaData);
    temp = temp->get_next();
  }
  return count;
}

size_t BlockList::getNumberOfFreeBlocks() const {
  MetaData *temp = block_list;
  size_t count = 0;
  while (temp != nullptr) {
    if (temp->get_is_free()) {
      count++;
    }
    temp = temp->get_next();
  }
  return count;
}

size_t BlockList::getNumberOfFreeBytes() const {
  MetaData *temp = block_list;
  size_t count = 0;
  while (temp != nullptr) {
    if (temp->get_is_free()) {
      count += temp->get_size() - sizeof(MetaData);
    }
    temp = temp->get_next();
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
  if (meta_data->get_size() >= mmap_size + sizeof(MetaData)) {
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
  size_t old_size = old_block->get_size();

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
  if (left && right && left->get_is_free() &&
      left->get_size() + old_block->get_size() >= size + sizeof(MetaData)) {
    bl.mergeBlocks(left, old_block);
    left->set_is_free(false);

    new_p = (char *)left + sizeof(MetaData);
  }

  // c
  else if (!right) {
    if (left && left->get_is_free()) {
      bl.mergeBlocks(left, old_block);
      old_block = left;
    }
    if (old_block->get_size() - sizeof(MetaData) < size) {
      bl.expandWilderness(size + sizeof(MetaData));
    }
    old_block->set_is_free(false);

    new_p = (char *)left + sizeof(MetaData);
  }

  // d
  else if (right && right->get_is_free() &&
           right->get_size() + old_block->get_size() >=
               size + sizeof(MetaData)) {
    bl.mergeBlocks(old_block, right);

    new_p = (char *)old_block + sizeof(MetaData);
  }

  // e
  else if (left && right && left->get_is_free() && right->get_is_free() &&
           right->get_size() + left->get_size() + old_block->get_size() >=
               size + sizeof(MetaData)) {
    bl.mergeBlocks(left, old_block);
    bl.mergeBlocks(left, right);
    left->set_is_free(false);

    new_p = (char *)left + sizeof(MetaData);
  }

  // f
  else if (wilderness && right == wilderness && right->get_is_free()) {
    if (left && left->get_is_free()) {
      bl.mergeBlocks(left, old_block);
      left->set_is_free(false);
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
