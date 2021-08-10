// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: sniffed_info.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_sniffed_5finfo_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_sniffed_5finfo_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3017000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3017001 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_sniffed_5finfo_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_sniffed_5finfo_2eproto {
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::AuxiliaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTable schema[2]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::FieldMetadata field_metadata[];
  static const ::PROTOBUF_NAMESPACE_ID::internal::SerializationTable serialization_table[];
  static const ::PROTOBUF_NAMESPACE_ID::uint32 offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_sniffed_5finfo_2eproto;
class Flow;
struct FlowDefaultTypeInternal;
extern FlowDefaultTypeInternal _Flow_default_instance_;
class FlowArray;
struct FlowArrayDefaultTypeInternal;
extern FlowArrayDefaultTypeInternal _FlowArray_default_instance_;
PROTOBUF_NAMESPACE_OPEN
template<> ::Flow* Arena::CreateMaybeMessage<::Flow>(Arena*);
template<> ::FlowArray* Arena::CreateMaybeMessage<::FlowArray>(Arena*);
PROTOBUF_NAMESPACE_CLOSE

// ===================================================================

class Flow final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:Flow) */ {
 public:
  inline Flow() : Flow(nullptr) {}
  ~Flow() override;
  explicit constexpr Flow(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  Flow(const Flow& from);
  Flow(Flow&& from) noexcept
    : Flow() {
    *this = ::std::move(from);
  }

  inline Flow& operator=(const Flow& from) {
    CopyFrom(from);
    return *this;
  }
  inline Flow& operator=(Flow&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const Flow& default_instance() {
    return *internal_default_instance();
  }
  static inline const Flow* internal_default_instance() {
    return reinterpret_cast<const Flow*>(
               &_Flow_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(Flow& a, Flow& b) {
    a.Swap(&b);
  }
  inline void Swap(Flow* other) {
    if (other == this) return;
    if (GetOwningArena() == other->GetOwningArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(Flow* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline Flow* New() const final {
    return new Flow();
  }

  Flow* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<Flow>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const Flow& from);
  void MergeFrom(const Flow& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(Flow* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "Flow";
  }
  protected:
  explicit Flow(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kSAddrFieldNumber = 1,
    kSPortFieldNumber = 2,
    kDAddrFieldNumber = 3,
    kDPortFieldNumber = 4,
    kServiceTypeFieldNumber = 7,
    kNumBytesFieldNumber = 5,
    kIsServerFieldNumber = 6,
    kRstFieldNumber = 8,
  };
  // string s_addr = 1;
  void clear_s_addr();
  const std::string& s_addr() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_s_addr(ArgT0&& arg0, ArgT... args);
  std::string* mutable_s_addr();
  PROTOBUF_FUTURE_MUST_USE_RESULT std::string* release_s_addr();
  void set_allocated_s_addr(std::string* s_addr);
  private:
  const std::string& _internal_s_addr() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_s_addr(const std::string& value);
  std::string* _internal_mutable_s_addr();
  public:

  // string s_port = 2;
  void clear_s_port();
  const std::string& s_port() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_s_port(ArgT0&& arg0, ArgT... args);
  std::string* mutable_s_port();
  PROTOBUF_FUTURE_MUST_USE_RESULT std::string* release_s_port();
  void set_allocated_s_port(std::string* s_port);
  private:
  const std::string& _internal_s_port() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_s_port(const std::string& value);
  std::string* _internal_mutable_s_port();
  public:

  // string d_addr = 3;
  void clear_d_addr();
  const std::string& d_addr() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_d_addr(ArgT0&& arg0, ArgT... args);
  std::string* mutable_d_addr();
  PROTOBUF_FUTURE_MUST_USE_RESULT std::string* release_d_addr();
  void set_allocated_d_addr(std::string* d_addr);
  private:
  const std::string& _internal_d_addr() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_d_addr(const std::string& value);
  std::string* _internal_mutable_d_addr();
  public:

  // string d_port = 4;
  void clear_d_port();
  const std::string& d_port() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_d_port(ArgT0&& arg0, ArgT... args);
  std::string* mutable_d_port();
  PROTOBUF_FUTURE_MUST_USE_RESULT std::string* release_d_port();
  void set_allocated_d_port(std::string* d_port);
  private:
  const std::string& _internal_d_port() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_d_port(const std::string& value);
  std::string* _internal_mutable_d_port();
  public:

  // string service_type = 7;
  void clear_service_type();
  const std::string& service_type() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_service_type(ArgT0&& arg0, ArgT... args);
  std::string* mutable_service_type();
  PROTOBUF_FUTURE_MUST_USE_RESULT std::string* release_service_type();
  void set_allocated_service_type(std::string* service_type);
  private:
  const std::string& _internal_service_type() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_service_type(const std::string& value);
  std::string* _internal_mutable_service_type();
  public:

  // int32 num_bytes = 5;
  void clear_num_bytes();
  ::PROTOBUF_NAMESPACE_ID::int32 num_bytes() const;
  void set_num_bytes(::PROTOBUF_NAMESPACE_ID::int32 value);
  private:
  ::PROTOBUF_NAMESPACE_ID::int32 _internal_num_bytes() const;
  void _internal_set_num_bytes(::PROTOBUF_NAMESPACE_ID::int32 value);
  public:

  // bool is_server = 6;
  void clear_is_server();
  bool is_server() const;
  void set_is_server(bool value);
  private:
  bool _internal_is_server() const;
  void _internal_set_is_server(bool value);
  public:

  // double rst = 8;
  void clear_rst();
  double rst() const;
  void set_rst(double value);
  private:
  double _internal_rst() const;
  void _internal_set_rst(double value);
  public:

  // @@protoc_insertion_point(class_scope:Flow)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr s_addr_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr s_port_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr d_addr_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr d_port_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr service_type_;
  ::PROTOBUF_NAMESPACE_ID::int32 num_bytes_;
  bool is_server_;
  double rst_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_sniffed_5finfo_2eproto;
};
// -------------------------------------------------------------------

class FlowArray final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:FlowArray) */ {
 public:
  inline FlowArray() : FlowArray(nullptr) {}
  ~FlowArray() override;
  explicit constexpr FlowArray(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  FlowArray(const FlowArray& from);
  FlowArray(FlowArray&& from) noexcept
    : FlowArray() {
    *this = ::std::move(from);
  }

  inline FlowArray& operator=(const FlowArray& from) {
    CopyFrom(from);
    return *this;
  }
  inline FlowArray& operator=(FlowArray&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const FlowArray& default_instance() {
    return *internal_default_instance();
  }
  static inline const FlowArray* internal_default_instance() {
    return reinterpret_cast<const FlowArray*>(
               &_FlowArray_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  friend void swap(FlowArray& a, FlowArray& b) {
    a.Swap(&b);
  }
  inline void Swap(FlowArray* other) {
    if (other == this) return;
    if (GetOwningArena() == other->GetOwningArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(FlowArray* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline FlowArray* New() const final {
    return new FlowArray();
  }

  FlowArray* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<FlowArray>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const FlowArray& from);
  void MergeFrom(const FlowArray& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(FlowArray* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "FlowArray";
  }
  protected:
  explicit FlowArray(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kFlowsFieldNumber = 1,
  };
  // repeated .Flow flows = 1;
  int flows_size() const;
  private:
  int _internal_flows_size() const;
  public:
  void clear_flows();
  ::Flow* mutable_flows(int index);
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::Flow >*
      mutable_flows();
  private:
  const ::Flow& _internal_flows(int index) const;
  ::Flow* _internal_add_flows();
  public:
  const ::Flow& flows(int index) const;
  ::Flow* add_flows();
  const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::Flow >&
      flows() const;

  // @@protoc_insertion_point(class_scope:FlowArray)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::Flow > flows_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_sniffed_5finfo_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// Flow

// string s_addr = 1;
inline void Flow::clear_s_addr() {
  s_addr_.ClearToEmpty();
}
inline const std::string& Flow::s_addr() const {
  // @@protoc_insertion_point(field_get:Flow.s_addr)
  return _internal_s_addr();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void Flow::set_s_addr(ArgT0&& arg0, ArgT... args) {
 
 s_addr_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:Flow.s_addr)
}
inline std::string* Flow::mutable_s_addr() {
  // @@protoc_insertion_point(field_mutable:Flow.s_addr)
  return _internal_mutable_s_addr();
}
inline const std::string& Flow::_internal_s_addr() const {
  return s_addr_.Get();
}
inline void Flow::_internal_set_s_addr(const std::string& value) {
  
  s_addr_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* Flow::_internal_mutable_s_addr() {
  
  return s_addr_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* Flow::release_s_addr() {
  // @@protoc_insertion_point(field_release:Flow.s_addr)
  return s_addr_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void Flow::set_allocated_s_addr(std::string* s_addr) {
  if (s_addr != nullptr) {
    
  } else {
    
  }
  s_addr_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), s_addr,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:Flow.s_addr)
}

// string s_port = 2;
inline void Flow::clear_s_port() {
  s_port_.ClearToEmpty();
}
inline const std::string& Flow::s_port() const {
  // @@protoc_insertion_point(field_get:Flow.s_port)
  return _internal_s_port();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void Flow::set_s_port(ArgT0&& arg0, ArgT... args) {
 
 s_port_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:Flow.s_port)
}
inline std::string* Flow::mutable_s_port() {
  // @@protoc_insertion_point(field_mutable:Flow.s_port)
  return _internal_mutable_s_port();
}
inline const std::string& Flow::_internal_s_port() const {
  return s_port_.Get();
}
inline void Flow::_internal_set_s_port(const std::string& value) {
  
  s_port_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* Flow::_internal_mutable_s_port() {
  
  return s_port_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* Flow::release_s_port() {
  // @@protoc_insertion_point(field_release:Flow.s_port)
  return s_port_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void Flow::set_allocated_s_port(std::string* s_port) {
  if (s_port != nullptr) {
    
  } else {
    
  }
  s_port_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), s_port,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:Flow.s_port)
}

// string d_addr = 3;
inline void Flow::clear_d_addr() {
  d_addr_.ClearToEmpty();
}
inline const std::string& Flow::d_addr() const {
  // @@protoc_insertion_point(field_get:Flow.d_addr)
  return _internal_d_addr();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void Flow::set_d_addr(ArgT0&& arg0, ArgT... args) {
 
 d_addr_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:Flow.d_addr)
}
inline std::string* Flow::mutable_d_addr() {
  // @@protoc_insertion_point(field_mutable:Flow.d_addr)
  return _internal_mutable_d_addr();
}
inline const std::string& Flow::_internal_d_addr() const {
  return d_addr_.Get();
}
inline void Flow::_internal_set_d_addr(const std::string& value) {
  
  d_addr_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* Flow::_internal_mutable_d_addr() {
  
  return d_addr_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* Flow::release_d_addr() {
  // @@protoc_insertion_point(field_release:Flow.d_addr)
  return d_addr_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void Flow::set_allocated_d_addr(std::string* d_addr) {
  if (d_addr != nullptr) {
    
  } else {
    
  }
  d_addr_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), d_addr,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:Flow.d_addr)
}

// string d_port = 4;
inline void Flow::clear_d_port() {
  d_port_.ClearToEmpty();
}
inline const std::string& Flow::d_port() const {
  // @@protoc_insertion_point(field_get:Flow.d_port)
  return _internal_d_port();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void Flow::set_d_port(ArgT0&& arg0, ArgT... args) {
 
 d_port_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:Flow.d_port)
}
inline std::string* Flow::mutable_d_port() {
  // @@protoc_insertion_point(field_mutable:Flow.d_port)
  return _internal_mutable_d_port();
}
inline const std::string& Flow::_internal_d_port() const {
  return d_port_.Get();
}
inline void Flow::_internal_set_d_port(const std::string& value) {
  
  d_port_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* Flow::_internal_mutable_d_port() {
  
  return d_port_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* Flow::release_d_port() {
  // @@protoc_insertion_point(field_release:Flow.d_port)
  return d_port_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void Flow::set_allocated_d_port(std::string* d_port) {
  if (d_port != nullptr) {
    
  } else {
    
  }
  d_port_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), d_port,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:Flow.d_port)
}

// int32 num_bytes = 5;
inline void Flow::clear_num_bytes() {
  num_bytes_ = 0;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 Flow::_internal_num_bytes() const {
  return num_bytes_;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 Flow::num_bytes() const {
  // @@protoc_insertion_point(field_get:Flow.num_bytes)
  return _internal_num_bytes();
}
inline void Flow::_internal_set_num_bytes(::PROTOBUF_NAMESPACE_ID::int32 value) {
  
  num_bytes_ = value;
}
inline void Flow::set_num_bytes(::PROTOBUF_NAMESPACE_ID::int32 value) {
  _internal_set_num_bytes(value);
  // @@protoc_insertion_point(field_set:Flow.num_bytes)
}

// bool is_server = 6;
inline void Flow::clear_is_server() {
  is_server_ = false;
}
inline bool Flow::_internal_is_server() const {
  return is_server_;
}
inline bool Flow::is_server() const {
  // @@protoc_insertion_point(field_get:Flow.is_server)
  return _internal_is_server();
}
inline void Flow::_internal_set_is_server(bool value) {
  
  is_server_ = value;
}
inline void Flow::set_is_server(bool value) {
  _internal_set_is_server(value);
  // @@protoc_insertion_point(field_set:Flow.is_server)
}

// string service_type = 7;
inline void Flow::clear_service_type() {
  service_type_.ClearToEmpty();
}
inline const std::string& Flow::service_type() const {
  // @@protoc_insertion_point(field_get:Flow.service_type)
  return _internal_service_type();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void Flow::set_service_type(ArgT0&& arg0, ArgT... args) {
 
 service_type_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:Flow.service_type)
}
inline std::string* Flow::mutable_service_type() {
  // @@protoc_insertion_point(field_mutable:Flow.service_type)
  return _internal_mutable_service_type();
}
inline const std::string& Flow::_internal_service_type() const {
  return service_type_.Get();
}
inline void Flow::_internal_set_service_type(const std::string& value) {
  
  service_type_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* Flow::_internal_mutable_service_type() {
  
  return service_type_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* Flow::release_service_type() {
  // @@protoc_insertion_point(field_release:Flow.service_type)
  return service_type_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void Flow::set_allocated_service_type(std::string* service_type) {
  if (service_type != nullptr) {
    
  } else {
    
  }
  service_type_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), service_type,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:Flow.service_type)
}

// double rst = 8;
inline void Flow::clear_rst() {
  rst_ = 0;
}
inline double Flow::_internal_rst() const {
  return rst_;
}
inline double Flow::rst() const {
  // @@protoc_insertion_point(field_get:Flow.rst)
  return _internal_rst();
}
inline void Flow::_internal_set_rst(double value) {
  
  rst_ = value;
}
inline void Flow::set_rst(double value) {
  _internal_set_rst(value);
  // @@protoc_insertion_point(field_set:Flow.rst)
}

// -------------------------------------------------------------------

// FlowArray

// repeated .Flow flows = 1;
inline int FlowArray::_internal_flows_size() const {
  return flows_.size();
}
inline int FlowArray::flows_size() const {
  return _internal_flows_size();
}
inline void FlowArray::clear_flows() {
  flows_.Clear();
}
inline ::Flow* FlowArray::mutable_flows(int index) {
  // @@protoc_insertion_point(field_mutable:FlowArray.flows)
  return flows_.Mutable(index);
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::Flow >*
FlowArray::mutable_flows() {
  // @@protoc_insertion_point(field_mutable_list:FlowArray.flows)
  return &flows_;
}
inline const ::Flow& FlowArray::_internal_flows(int index) const {
  return flows_.Get(index);
}
inline const ::Flow& FlowArray::flows(int index) const {
  // @@protoc_insertion_point(field_get:FlowArray.flows)
  return _internal_flows(index);
}
inline ::Flow* FlowArray::_internal_add_flows() {
  return flows_.Add();
}
inline ::Flow* FlowArray::add_flows() {
  // @@protoc_insertion_point(field_add:FlowArray.flows)
  return _internal_add_flows();
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::Flow >&
FlowArray::flows() const {
  // @@protoc_insertion_point(field_list:FlowArray.flows)
  return flows_;
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)


// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_sniffed_5finfo_2eproto
