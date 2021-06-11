// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: sniffed_info.proto

#include "sniffed_info.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG
constexpr Flow::Flow(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : s_addr_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , s_port_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , d_addr_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , d_port_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , rst_(0)
  , num_bytes_(0){}
struct FlowDefaultTypeInternal {
  constexpr FlowDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~FlowDefaultTypeInternal() {}
  union {
    Flow _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT FlowDefaultTypeInternal _Flow_default_instance_;
constexpr FlowArray::FlowArray(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : flows_(){}
struct FlowArrayDefaultTypeInternal {
  constexpr FlowArrayDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~FlowArrayDefaultTypeInternal() {}
  union {
    FlowArray _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT FlowArrayDefaultTypeInternal _FlowArray_default_instance_;
constexpr AckTime::AckTime(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : sec_(0)
  , usec_(0){}
struct AckTimeDefaultTypeInternal {
  constexpr AckTimeDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~AckTimeDefaultTypeInternal() {}
  union {
    AckTime _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT AckTimeDefaultTypeInternal _AckTime_default_instance_;
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_sniffed_5finfo_2eproto[3];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_sniffed_5finfo_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_sniffed_5finfo_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_sniffed_5finfo_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::Flow, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::Flow, s_addr_),
  PROTOBUF_FIELD_OFFSET(::Flow, s_port_),
  PROTOBUF_FIELD_OFFSET(::Flow, d_addr_),
  PROTOBUF_FIELD_OFFSET(::Flow, d_port_),
  PROTOBUF_FIELD_OFFSET(::Flow, num_bytes_),
  PROTOBUF_FIELD_OFFSET(::Flow, rst_),
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::FlowArray, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::FlowArray, flows_),
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::AckTime, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::AckTime, sec_),
  PROTOBUF_FIELD_OFFSET(::AckTime, usec_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::Flow)},
  { 11, -1, sizeof(::FlowArray)},
  { 17, -1, sizeof(::AckTime)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::_Flow_default_instance_),
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::_FlowArray_default_instance_),
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::_AckTime_default_instance_),
};

const char descriptor_table_protodef_sniffed_5finfo_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\022sniffed_info.proto\"f\n\004Flow\022\016\n\006s_addr\030\001"
  " \001(\t\022\016\n\006s_port\030\002 \001(\t\022\016\n\006d_addr\030\003 \001(\t\022\016\n\006"
  "d_port\030\004 \001(\t\022\021\n\tnum_bytes\030\005 \001(\005\022\013\n\003rst\030\007"
  " \001(\001\"!\n\tFlowArray\022\024\n\005flows\030\001 \003(\0132\005.Flow\""
  "$\n\007AckTime\022\013\n\003sec\030\001 \001(\005\022\014\n\004usec\030\002 \001(\005b\006p"
  "roto3"
  ;
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_sniffed_5finfo_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_sniffed_5finfo_2eproto = {
  false, false, 205, descriptor_table_protodef_sniffed_5finfo_2eproto, "sniffed_info.proto", 
  &descriptor_table_sniffed_5finfo_2eproto_once, nullptr, 0, 3,
  schemas, file_default_instances, TableStruct_sniffed_5finfo_2eproto::offsets,
  file_level_metadata_sniffed_5finfo_2eproto, file_level_enum_descriptors_sniffed_5finfo_2eproto, file_level_service_descriptors_sniffed_5finfo_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_sniffed_5finfo_2eproto_getter() {
  return &descriptor_table_sniffed_5finfo_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_sniffed_5finfo_2eproto(&descriptor_table_sniffed_5finfo_2eproto);

// ===================================================================

class Flow::_Internal {
 public:
};

Flow::Flow(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:Flow)
}
Flow::Flow(const Flow& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  s_addr_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_s_addr().empty()) {
    s_addr_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_s_addr(), 
      GetArenaForAllocation());
  }
  s_port_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_s_port().empty()) {
    s_port_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_s_port(), 
      GetArenaForAllocation());
  }
  d_addr_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_d_addr().empty()) {
    d_addr_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_d_addr(), 
      GetArenaForAllocation());
  }
  d_port_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_d_port().empty()) {
    d_port_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_d_port(), 
      GetArenaForAllocation());
  }
  ::memcpy(&rst_, &from.rst_,
    static_cast<size_t>(reinterpret_cast<char*>(&num_bytes_) -
    reinterpret_cast<char*>(&rst_)) + sizeof(num_bytes_));
  // @@protoc_insertion_point(copy_constructor:Flow)
}

void Flow::SharedCtor() {
s_addr_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
s_port_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
d_addr_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
d_port_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
::memset(reinterpret_cast<char*>(this) + static_cast<size_t>(
    reinterpret_cast<char*>(&rst_) - reinterpret_cast<char*>(this)),
    0, static_cast<size_t>(reinterpret_cast<char*>(&num_bytes_) -
    reinterpret_cast<char*>(&rst_)) + sizeof(num_bytes_));
}

Flow::~Flow() {
  // @@protoc_insertion_point(destructor:Flow)
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

void Flow::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  s_addr_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  s_port_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  d_addr_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  d_port_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void Flow::ArenaDtor(void* object) {
  Flow* _this = reinterpret_cast< Flow* >(object);
  (void)_this;
}
void Flow::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void Flow::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void Flow::Clear() {
// @@protoc_insertion_point(message_clear_start:Flow)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  s_addr_.ClearToEmpty();
  s_port_.ClearToEmpty();
  d_addr_.ClearToEmpty();
  d_port_.ClearToEmpty();
  ::memset(&rst_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&num_bytes_) -
      reinterpret_cast<char*>(&rst_)) + sizeof(num_bytes_));
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Flow::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // string s_addr = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          auto str = _internal_mutable_s_addr();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(::PROTOBUF_NAMESPACE_ID::internal::VerifyUTF8(str, "Flow.s_addr"));
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // string s_port = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          auto str = _internal_mutable_s_port();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(::PROTOBUF_NAMESPACE_ID::internal::VerifyUTF8(str, "Flow.s_port"));
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // string d_addr = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 26)) {
          auto str = _internal_mutable_d_addr();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(::PROTOBUF_NAMESPACE_ID::internal::VerifyUTF8(str, "Flow.d_addr"));
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // string d_port = 4;
      case 4:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 34)) {
          auto str = _internal_mutable_d_port();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(::PROTOBUF_NAMESPACE_ID::internal::VerifyUTF8(str, "Flow.d_port"));
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // int32 num_bytes = 5;
      case 5:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 40)) {
          num_bytes_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // double rst = 7;
      case 7:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 57)) {
          rst_ = ::PROTOBUF_NAMESPACE_ID::internal::UnalignedLoad<double>(ptr);
          ptr += sizeof(double);
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag == 0) || ((tag & 7) == 4)) {
          CHK_(ptr);
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* Flow::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:Flow)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // string s_addr = 1;
  if (!this->s_addr().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_s_addr().data(), static_cast<int>(this->_internal_s_addr().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "Flow.s_addr");
    target = stream->WriteStringMaybeAliased(
        1, this->_internal_s_addr(), target);
  }

  // string s_port = 2;
  if (!this->s_port().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_s_port().data(), static_cast<int>(this->_internal_s_port().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "Flow.s_port");
    target = stream->WriteStringMaybeAliased(
        2, this->_internal_s_port(), target);
  }

  // string d_addr = 3;
  if (!this->d_addr().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_d_addr().data(), static_cast<int>(this->_internal_d_addr().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "Flow.d_addr");
    target = stream->WriteStringMaybeAliased(
        3, this->_internal_d_addr(), target);
  }

  // string d_port = 4;
  if (!this->d_port().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_d_port().data(), static_cast<int>(this->_internal_d_port().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "Flow.d_port");
    target = stream->WriteStringMaybeAliased(
        4, this->_internal_d_port(), target);
  }

  // int32 num_bytes = 5;
  if (this->num_bytes() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt32ToArray(5, this->_internal_num_bytes(), target);
  }

  // double rst = 7;
  if (!(this->rst() <= 0 && this->rst() >= 0)) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteDoubleToArray(7, this->_internal_rst(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:Flow)
  return target;
}

size_t Flow::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:Flow)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string s_addr = 1;
  if (!this->s_addr().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_s_addr());
  }

  // string s_port = 2;
  if (!this->s_port().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_s_port());
  }

  // string d_addr = 3;
  if (!this->d_addr().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_d_addr());
  }

  // string d_port = 4;
  if (!this->d_port().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_d_port());
  }

  // double rst = 7;
  if (!(this->rst() <= 0 && this->rst() >= 0)) {
    total_size += 1 + 8;
  }

  // int32 num_bytes = 5;
  if (this->num_bytes() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int32Size(
        this->_internal_num_bytes());
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void Flow::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:Flow)
  GOOGLE_DCHECK_NE(&from, this);
  const Flow* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<Flow>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:Flow)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:Flow)
    MergeFrom(*source);
  }
}

void Flow::MergeFrom(const Flow& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:Flow)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from.s_addr().empty()) {
    _internal_set_s_addr(from._internal_s_addr());
  }
  if (!from.s_port().empty()) {
    _internal_set_s_port(from._internal_s_port());
  }
  if (!from.d_addr().empty()) {
    _internal_set_d_addr(from._internal_d_addr());
  }
  if (!from.d_port().empty()) {
    _internal_set_d_port(from._internal_d_port());
  }
  if (!(from.rst() <= 0 && from.rst() >= 0)) {
    _internal_set_rst(from._internal_rst());
  }
  if (from.num_bytes() != 0) {
    _internal_set_num_bytes(from._internal_num_bytes());
  }
}

void Flow::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:Flow)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void Flow::CopyFrom(const Flow& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:Flow)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Flow::IsInitialized() const {
  return true;
}

void Flow::InternalSwap(Flow* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &s_addr_, GetArenaForAllocation(),
      &other->s_addr_, other->GetArenaForAllocation()
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &s_port_, GetArenaForAllocation(),
      &other->s_port_, other->GetArenaForAllocation()
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &d_addr_, GetArenaForAllocation(),
      &other->d_addr_, other->GetArenaForAllocation()
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &d_port_, GetArenaForAllocation(),
      &other->d_port_, other->GetArenaForAllocation()
  );
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(Flow, num_bytes_)
      + sizeof(Flow::num_bytes_)
      - PROTOBUF_FIELD_OFFSET(Flow, rst_)>(
          reinterpret_cast<char*>(&rst_),
          reinterpret_cast<char*>(&other->rst_));
}

::PROTOBUF_NAMESPACE_ID::Metadata Flow::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_sniffed_5finfo_2eproto_getter, &descriptor_table_sniffed_5finfo_2eproto_once,
      file_level_metadata_sniffed_5finfo_2eproto[0]);
}

// ===================================================================

class FlowArray::_Internal {
 public:
};

FlowArray::FlowArray(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena),
  flows_(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:FlowArray)
}
FlowArray::FlowArray(const FlowArray& from)
  : ::PROTOBUF_NAMESPACE_ID::Message(),
      flows_(from.flows_) {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:FlowArray)
}

void FlowArray::SharedCtor() {
}

FlowArray::~FlowArray() {
  // @@protoc_insertion_point(destructor:FlowArray)
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

void FlowArray::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
}

void FlowArray::ArenaDtor(void* object) {
  FlowArray* _this = reinterpret_cast< FlowArray* >(object);
  (void)_this;
}
void FlowArray::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void FlowArray::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void FlowArray::Clear() {
// @@protoc_insertion_point(message_clear_start:FlowArray)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  flows_.Clear();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* FlowArray::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // repeated .Flow flows = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          ptr -= 1;
          do {
            ptr += 1;
            ptr = ctx->ParseMessage(_internal_add_flows(), ptr);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<10>(ptr));
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag == 0) || ((tag & 7) == 4)) {
          CHK_(ptr);
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* FlowArray::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:FlowArray)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated .Flow flows = 1;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->_internal_flows_size()); i < n; i++) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(1, this->_internal_flows(i), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:FlowArray)
  return target;
}

size_t FlowArray::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:FlowArray)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated .Flow flows = 1;
  total_size += 1UL * this->_internal_flows_size();
  for (const auto& msg : this->flows_) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(msg);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void FlowArray::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:FlowArray)
  GOOGLE_DCHECK_NE(&from, this);
  const FlowArray* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<FlowArray>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:FlowArray)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:FlowArray)
    MergeFrom(*source);
  }
}

void FlowArray::MergeFrom(const FlowArray& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:FlowArray)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  flows_.MergeFrom(from.flows_);
}

void FlowArray::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:FlowArray)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void FlowArray::CopyFrom(const FlowArray& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:FlowArray)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool FlowArray::IsInitialized() const {
  return true;
}

void FlowArray::InternalSwap(FlowArray* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  flows_.InternalSwap(&other->flows_);
}

::PROTOBUF_NAMESPACE_ID::Metadata FlowArray::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_sniffed_5finfo_2eproto_getter, &descriptor_table_sniffed_5finfo_2eproto_once,
      file_level_metadata_sniffed_5finfo_2eproto[1]);
}

// ===================================================================

class AckTime::_Internal {
 public:
};

AckTime::AckTime(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:AckTime)
}
AckTime::AckTime(const AckTime& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ::memcpy(&sec_, &from.sec_,
    static_cast<size_t>(reinterpret_cast<char*>(&usec_) -
    reinterpret_cast<char*>(&sec_)) + sizeof(usec_));
  // @@protoc_insertion_point(copy_constructor:AckTime)
}

void AckTime::SharedCtor() {
::memset(reinterpret_cast<char*>(this) + static_cast<size_t>(
    reinterpret_cast<char*>(&sec_) - reinterpret_cast<char*>(this)),
    0, static_cast<size_t>(reinterpret_cast<char*>(&usec_) -
    reinterpret_cast<char*>(&sec_)) + sizeof(usec_));
}

AckTime::~AckTime() {
  // @@protoc_insertion_point(destructor:AckTime)
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

void AckTime::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
}

void AckTime::ArenaDtor(void* object) {
  AckTime* _this = reinterpret_cast< AckTime* >(object);
  (void)_this;
}
void AckTime::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void AckTime::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void AckTime::Clear() {
// @@protoc_insertion_point(message_clear_start:AckTime)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  ::memset(&sec_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&usec_) -
      reinterpret_cast<char*>(&sec_)) + sizeof(usec_));
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* AckTime::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // int32 sec = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 8)) {
          sec_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // int32 usec = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 16)) {
          usec_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag == 0) || ((tag & 7) == 4)) {
          CHK_(ptr);
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* AckTime::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:AckTime)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // int32 sec = 1;
  if (this->sec() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt32ToArray(1, this->_internal_sec(), target);
  }

  // int32 usec = 2;
  if (this->usec() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt32ToArray(2, this->_internal_usec(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:AckTime)
  return target;
}

size_t AckTime::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:AckTime)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // int32 sec = 1;
  if (this->sec() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int32Size(
        this->_internal_sec());
  }

  // int32 usec = 2;
  if (this->usec() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int32Size(
        this->_internal_usec());
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void AckTime::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:AckTime)
  GOOGLE_DCHECK_NE(&from, this);
  const AckTime* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<AckTime>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:AckTime)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:AckTime)
    MergeFrom(*source);
  }
}

void AckTime::MergeFrom(const AckTime& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:AckTime)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.sec() != 0) {
    _internal_set_sec(from._internal_sec());
  }
  if (from.usec() != 0) {
    _internal_set_usec(from._internal_usec());
  }
}

void AckTime::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:AckTime)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void AckTime::CopyFrom(const AckTime& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:AckTime)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool AckTime::IsInitialized() const {
  return true;
}

void AckTime::InternalSwap(AckTime* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(AckTime, usec_)
      + sizeof(AckTime::usec_)
      - PROTOBUF_FIELD_OFFSET(AckTime, sec_)>(
          reinterpret_cast<char*>(&sec_),
          reinterpret_cast<char*>(&other->sec_));
}

::PROTOBUF_NAMESPACE_ID::Metadata AckTime::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_sniffed_5finfo_2eproto_getter, &descriptor_table_sniffed_5finfo_2eproto_once,
      file_level_metadata_sniffed_5finfo_2eproto[2]);
}

// @@protoc_insertion_point(namespace_scope)
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::Flow* Arena::CreateMaybeMessage< ::Flow >(Arena* arena) {
  return Arena::CreateMessageInternal< ::Flow >(arena);
}
template<> PROTOBUF_NOINLINE ::FlowArray* Arena::CreateMaybeMessage< ::FlowArray >(Arena* arena) {
  return Arena::CreateMessageInternal< ::FlowArray >(arena);
}
template<> PROTOBUF_NOINLINE ::AckTime* Arena::CreateMaybeMessage< ::AckTime >(Arena* arena) {
  return Arena::CreateMessageInternal< ::AckTime >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
