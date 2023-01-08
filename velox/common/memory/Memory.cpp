/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "velox/common/memory/Memory.h"

#include "velox/common/base/BitUtil.h"

namespace facebook {
namespace velox {
namespace memory {
namespace {
#define VELOX_MEM_MANAGER_CAP_EXCEEDED(cap)                         \
  _VELOX_THROW(                                                     \
      ::facebook::velox::VeloxRuntimeError,                         \
      ::facebook::velox::error_source::kErrorSourceRuntime.c_str(), \
      ::facebook::velox::error_code::kMemCapExceeded.c_str(),       \
      /* isRetriable */ true,                                       \
      "Exceeded memory manager cap of {} MB",                       \
      (cap) / 1024 / 1024);

constexpr folly::StringPiece kRootNodeName{"__root__"};
} // namespace

MemoryPool::MemoryPool(
    const std::string& name,
    std::shared_ptr<MemoryPool> parent,
    const Options& options)
    : name_(name), alignment_{options.alignment}, parent_(std::move(parent)) {
  MemoryAllocator::alignmentCheck(0, alignment_);
}

MemoryPool::~MemoryPool() {
  VELOX_CHECK(children_.empty());
  if (parent_ != nullptr) {
    parent_->dropChild(this);
  }
}

const std::string& MemoryPool::name() const {
  return name_;
}

MemoryPool* MemoryPool::parent() const {
  return parent_.get();
}

uint64_t MemoryPool::getChildCount() const {
  folly::SharedMutex::ReadHolder guard{childrenMutex_};
  return children_.size();
}

void MemoryPool::visitChildren(
    std::function<void(MemoryPool* FOLLY_NONNULL)> visitor) const {
  folly::SharedMutex::ReadHolder guard{childrenMutex_};
  for (const auto& child : children_) {
    visitor(child);
  }
}

std::shared_ptr<MemoryPool> MemoryPool::addChild(const std::string& name) {
  folly::SharedMutex::WriteHolder guard{childrenMutex_};
  // Upon name collision we would throw and not modify the map.
  auto child = genChild(shared_from_this(), name);
  if (auto usageTracker = getMemoryUsageTracker()) {
    child->setMemoryUsageTracker(usageTracker->addChild());
  }
  children_.emplace_back(child.get());
  return child;
}

void MemoryPool::dropChild(const MemoryPool* FOLLY_NONNULL child) {
  folly::SharedMutex::WriteHolder guard{childrenMutex_};
  // Implicitly synchronized in dtor of child so it's impossible for
  // MemoryManager to access after destruction of child.
  auto iter = std::find_if(
      children_.begin(), children_.end(), [child](const MemoryPool* e) {
        return e == child;
      });
  VELOX_CHECK(iter != children_.end());
  children_.erase(iter);
}

size_t MemoryPool::getPreferredSize(size_t size) {
  if (size < 8) {
    return 8;
  }
  int32_t bits = 63 - bits::countLeadingZeros(size);
  size_t lower = 1ULL << bits;
  // Size is a power of 2.
  if (lower == size) {
    return size;
  }
  // If size is below 1.5 * previous power of two, return 1.5 *
  // the previous power of two, else the next power of 2.
  if (lower + (lower / 2) >= size) {
    return lower + (lower / 2);
  }
  return lower * 2;
}

MemoryPoolImpl::MemoryPoolImpl(
    MemoryManager& memoryManager,
    const std::string& name,
    std::shared_ptr<MemoryPool> parent,
    const Options& options)
    : MemoryPool{name, parent, options},
      memoryManager_{memoryManager},
      localMemoryUsage_{},
      allocator_{memoryManager_.getAllocator()} {}

MemoryPoolImpl::~MemoryPoolImpl() {
  if (const auto& tracker = getMemoryUsageTracker()) {
    // TODO: change to check reserved bytes which including the unused
    // reservation.
    auto remainingBytes = tracker->currentBytes();
    VELOX_CHECK_EQ(
        0,
        remainingBytes,
        "Memory pool should be destroyed only after all allocated memory has been freed. Remaining bytes allocated: {}, cumulative bytes allocated: {}, number of allocations: {}",
        remainingBytes,
        tracker->cumulativeBytes(),
        tracker->numAllocs());
  }
}

/* static */
int64_t MemoryPoolImpl::sizeAlign(int64_t size) {
  const auto remainder = size % alignment_;
  return (remainder == 0) ? size : (size + alignment_ - remainder);
}

void* MemoryPoolImpl::allocate(int64_t size) {
  const auto alignedSize = sizeAlign(size);
  reserve(alignedSize);
  return allocator_.allocateBytes(alignedSize, alignment_);
}

void* MemoryPoolImpl::allocateZeroFilled(int64_t numEntries, int64_t sizeEach) {
  const auto alignedSize = sizeAlign(sizeEach * numEntries);
  reserve(alignedSize);
  return allocator_.allocateZeroFilled(alignedSize);
}

void* MemoryPoolImpl::reallocate(
    void* FOLLY_NULLABLE p,
    int64_t size,
    int64_t newSize) {
  auto alignedSize = sizeAlign(size);
  auto alignedNewSize = sizeAlign(newSize);
  const int64_t difference = alignedNewSize - alignedSize;
  if (FOLLY_UNLIKELY(difference <= 0)) {
    // Track and pretend the shrink took place for accounting purposes.
    release(-difference);
    return p;
  }

  reserve(difference);
  void* newP =
      allocator_.reallocateBytes(p, alignedSize, alignedNewSize, alignment_);
  if (FOLLY_UNLIKELY(newP == nullptr)) {
    free(p, alignedSize);
    auto errorMessage = fmt::format(
        MEM_CAP_EXCEEDED_ERROR_FORMAT,
        // This is not accurate either way. We'll make it the proper memory
        // quota when we migrate all of capping and tracking to memory tracker.
        succinctBytes(getMemoryUsageTracker()->maxMemory()),
        succinctBytes(difference));
    VELOX_MEM_CAP_EXCEEDED(errorMessage);
  }
  return newP;
}

void MemoryPoolImpl::free(void* p, int64_t size) {
  const auto alignedSize = sizeAlign(size);
  allocator_.freeBytes(p, alignedSize);
  release(alignedSize);
}

bool MemoryPoolImpl::allocateNonContiguous(
    MachinePageCount numPages,
    MemoryAllocator::Allocation& out,
    MachinePageCount minSizeClass) {
  if (!allocator_.allocateNonContiguous(
          numPages,
          out,
          [this](int64_t allocBytes, bool preAllocate) {
            if (memoryUsageTracker_ != nullptr) {
              memoryUsageTracker_->update(
                  preAllocate ? allocBytes : -allocBytes);
            }
          },
          minSizeClass)) {
    VELOX_CHECK(out.empty());
    return false;
  }
  VELOX_CHECK(!out.empty());
  VELOX_CHECK_NULL(out.pool());
  out.setPool(this);
  return true;
}

void MemoryPoolImpl::freeNonContiguous(
    MemoryAllocator::Allocation& allocation) {
  const int64_t freedBytes = allocator_.freeNonContiguous(allocation);
  VELOX_CHECK(allocation.empty());
  if (memoryUsageTracker_ != nullptr) {
    memoryUsageTracker_->update(-freedBytes);
  }
}

MachinePageCount MemoryPoolImpl::largestSizeClass() const {
  return allocator_.largestSizeClass();
}

const std::vector<MachinePageCount>& MemoryPoolImpl::sizeClasses() const {
  return allocator_.sizeClasses();
}

bool MemoryPoolImpl::allocateContiguous(
    MachinePageCount numPages,
    MemoryAllocator::ContiguousAllocation& out) {
  if (!allocator_.allocateContiguous(
          numPages, nullptr, out, [this](int64_t allocBytes, bool preAlloc) {
            if (memoryUsageTracker_) {
              memoryUsageTracker_->update(preAlloc ? allocBytes : -allocBytes);
            }
          })) {
    VELOX_CHECK(out.empty());
    return false;
  }
  VELOX_CHECK(!out.empty());
  VELOX_CHECK_NULL(out.pool());
  out.setPool(this);
  return true;
}

void MemoryPoolImpl::freeContiguous(
    MemoryAllocator::ContiguousAllocation& allocation) {
  const int64_t bytesToFree = allocation.size();
  allocator_.freeContiguous(allocation);
  VELOX_CHECK(allocation.empty());
  if (memoryUsageTracker_ != nullptr) {
    memoryUsageTracker_->update(-bytesToFree);
  }
}

int64_t MemoryPoolImpl::getCurrentBytes() const {
  return getAggregateBytes();
}

int64_t MemoryPoolImpl::getMaxBytes() const {
  return std::max(getSubtreeMaxBytes(), localMemoryUsage_.getMaxBytes());
}

void MemoryPoolImpl::setMemoryUsageTracker(
    const std::shared_ptr<MemoryUsageTracker>& tracker) {
  const auto currentBytes = getCurrentBytes();
  if (memoryUsageTracker_) {
    memoryUsageTracker_->update(-currentBytes);
  }
  memoryUsageTracker_ = tracker;
  memoryUsageTracker_->update(currentBytes);
}

const std::shared_ptr<MemoryUsageTracker>&
MemoryPoolImpl::getMemoryUsageTracker() const {
  return memoryUsageTracker_;
}

int64_t MemoryPoolImpl::updateSubtreeMemoryUsage(int64_t size) {
  int64_t aggregateBytes;
  updateSubtreeMemoryUsage([&aggregateBytes, size](MemoryUsage& subtreeUsage) {
    aggregateBytes = subtreeUsage.getCurrentBytes() + size;
    subtreeUsage.setCurrentBytes(aggregateBytes);
  });
  return aggregateBytes;
}

uint16_t MemoryPoolImpl::getAlignment() const {
  return alignment_;
}

std::shared_ptr<MemoryPool> MemoryPoolImpl::genChild(
    std::shared_ptr<MemoryPool> parent,
    const std::string& name) {
  return std::make_shared<MemoryPoolImpl>(
      memoryManager_, name, parent, Options{.alignment = alignment_});
}

const MemoryUsage& MemoryPoolImpl::getLocalMemoryUsage() const {
  return localMemoryUsage_;
}

int64_t MemoryPoolImpl::getAggregateBytes() const {
  int64_t aggregateBytes = localMemoryUsage_.getCurrentBytes();
  accessSubtreeMemoryUsage([&aggregateBytes](const MemoryUsage& subtreeUsage) {
    aggregateBytes += subtreeUsage.getCurrentBytes();
  });
  return aggregateBytes;
}

int64_t MemoryPoolImpl::getSubtreeMaxBytes() const {
  int64_t maxBytes;
  accessSubtreeMemoryUsage([&maxBytes](const MemoryUsage& subtreeUsage) {
    maxBytes = subtreeUsage.getMaxBytes();
  });
  return maxBytes;
}

void MemoryPoolImpl::accessSubtreeMemoryUsage(
    std::function<void(const MemoryUsage&)> visitor) const {
  folly::SharedMutex::ReadHolder readLock{subtreeUsageMutex_};
  visitor(subtreeMemoryUsage_);
}

void MemoryPoolImpl::updateSubtreeMemoryUsage(
    std::function<void(MemoryUsage&)> visitor) {
  folly::SharedMutex::WriteHolder writeLock{subtreeUsageMutex_};
  visitor(subtreeMemoryUsage_);
}

void MemoryPoolImpl::reserve(int64_t size) {
  if (memoryUsageTracker_) {
    memoryUsageTracker_->update(size);
  }
  localMemoryUsage_.incrementCurrentBytes(size);

  bool success = memoryManager_.reserve(size);
  if (UNLIKELY(!success)) {
    // NOTE: If we can make the reserve and release a single transaction we
    // would have more accurate aggregates in intermediate states. However, this
    // is low-pri because we can only have inflated aggregates, and be on the
    // more conservative side.
    release(size);
    VELOX_MEM_MANAGER_CAP_EXCEEDED(memoryManager_.getMemoryQuota());
  }
}

void MemoryPoolImpl::release(int64_t size) {
  memoryManager_.release(size);
  localMemoryUsage_.incrementCurrentBytes(-size);
  if (memoryUsageTracker_) {
    memoryUsageTracker_->update(-size);
  }
}

MemoryManager::MemoryManager(const Options& options)
    : allocator_{options.allocator->shared_from_this()},
      memoryQuota_{options.capacity},
      alignment_(std::max(MemoryAllocator::kMinAlignment, options.alignment)),
      root_{std::make_shared<MemoryPoolImpl>(
          *this,
          kRootNodeName.str(),
          nullptr,
          MemoryPool::Options{alignment_, memoryQuota_})} {
  VELOX_CHECK_NOT_NULL(allocator_);
  VELOX_USER_CHECK_GE(memoryQuota_, 0);
  MemoryAllocator::alignmentCheck(0, alignment_);
}

MemoryManager::~MemoryManager() {
  auto currentBytes = getTotalBytes();
  if (currentBytes > 0) {
    LOG(WARNING) << "Leaked total memory of " << currentBytes << " bytes.";
  }
}

int64_t MemoryManager::getMemoryQuota() const {
  return memoryQuota_;
}

uint16_t MemoryManager::alignment() const {
  return alignment_;
}

MemoryPool& MemoryManager::getRoot() const {
  return *root_;
}

std::shared_ptr<MemoryPool> MemoryManager::getChild(int64_t cap) {
  return root_->addChild(fmt::format(
      "default_usage_node_{}",
      folly::to<std::string>(folly::Random::rand64())));
}

int64_t MemoryManager::getTotalBytes() const {
  return totalBytes_.load(std::memory_order_relaxed);
}

bool MemoryManager::reserve(int64_t size) {
  return totalBytes_.fetch_add(size, std::memory_order_relaxed) + size <=
      memoryQuota_;
}

void MemoryManager::release(int64_t size) {
  totalBytes_.fetch_sub(size, std::memory_order_relaxed);
}

MemoryAllocator& MemoryManager::getAllocator() {
  return *allocator_;
}

IMemoryManager& getProcessDefaultMemoryManager() {
  return MemoryManager::getInstance();
}

std::shared_ptr<MemoryPool> getDefaultMemoryPool(int64_t cap) {
  auto& memoryManager = getProcessDefaultMemoryManager();
  return memoryManager.getChild(cap);
}

} // namespace memory
} // namespace velox
} // namespace facebook
