// Generated by Molecule 0.7.2

// #define MOLECULEC_VERSION 7002
#define MOLECULE_API_VERSION_MIN 7000

#include "molecule_reader.h"
#include "molecule_builder.h"

#ifndef PROTOCOL_H
#define PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef MOLECULE_API_DECORATOR
#define __DEFINE_MOLECULE_API_DECORATOR_PROTOCOL
#define MOLECULE_API_DECORATOR
#endif /* MOLECULE_API_DECORATOR */

/*
 * Reader APIs
 */

#define                                 MolReader_Hash_verify(s, c)                     mol_verify_fixed_size(s, 32)
#define                                 MolReader_Hash_get_nth0(s)                      mol_slice_by_offset(s, 0, 1)
#define                                 MolReader_Hash_get_nth1(s)                      mol_slice_by_offset(s, 1, 1)
#define                                 MolReader_Hash_get_nth2(s)                      mol_slice_by_offset(s, 2, 1)
#define                                 MolReader_Hash_get_nth3(s)                      mol_slice_by_offset(s, 3, 1)
#define                                 MolReader_Hash_get_nth4(s)                      mol_slice_by_offset(s, 4, 1)
#define                                 MolReader_Hash_get_nth5(s)                      mol_slice_by_offset(s, 5, 1)
#define                                 MolReader_Hash_get_nth6(s)                      mol_slice_by_offset(s, 6, 1)
#define                                 MolReader_Hash_get_nth7(s)                      mol_slice_by_offset(s, 7, 1)
#define                                 MolReader_Hash_get_nth8(s)                      mol_slice_by_offset(s, 8, 1)
#define                                 MolReader_Hash_get_nth9(s)                      mol_slice_by_offset(s, 9, 1)
#define                                 MolReader_Hash_get_nth10(s)                     mol_slice_by_offset(s, 10, 1)
#define                                 MolReader_Hash_get_nth11(s)                     mol_slice_by_offset(s, 11, 1)
#define                                 MolReader_Hash_get_nth12(s)                     mol_slice_by_offset(s, 12, 1)
#define                                 MolReader_Hash_get_nth13(s)                     mol_slice_by_offset(s, 13, 1)
#define                                 MolReader_Hash_get_nth14(s)                     mol_slice_by_offset(s, 14, 1)
#define                                 MolReader_Hash_get_nth15(s)                     mol_slice_by_offset(s, 15, 1)
#define                                 MolReader_Hash_get_nth16(s)                     mol_slice_by_offset(s, 16, 1)
#define                                 MolReader_Hash_get_nth17(s)                     mol_slice_by_offset(s, 17, 1)
#define                                 MolReader_Hash_get_nth18(s)                     mol_slice_by_offset(s, 18, 1)
#define                                 MolReader_Hash_get_nth19(s)                     mol_slice_by_offset(s, 19, 1)
#define                                 MolReader_Hash_get_nth20(s)                     mol_slice_by_offset(s, 20, 1)
#define                                 MolReader_Hash_get_nth21(s)                     mol_slice_by_offset(s, 21, 1)
#define                                 MolReader_Hash_get_nth22(s)                     mol_slice_by_offset(s, 22, 1)
#define                                 MolReader_Hash_get_nth23(s)                     mol_slice_by_offset(s, 23, 1)
#define                                 MolReader_Hash_get_nth24(s)                     mol_slice_by_offset(s, 24, 1)
#define                                 MolReader_Hash_get_nth25(s)                     mol_slice_by_offset(s, 25, 1)
#define                                 MolReader_Hash_get_nth26(s)                     mol_slice_by_offset(s, 26, 1)
#define                                 MolReader_Hash_get_nth27(s)                     mol_slice_by_offset(s, 27, 1)
#define                                 MolReader_Hash_get_nth28(s)                     mol_slice_by_offset(s, 28, 1)
#define                                 MolReader_Hash_get_nth29(s)                     mol_slice_by_offset(s, 29, 1)
#define                                 MolReader_Hash_get_nth30(s)                     mol_slice_by_offset(s, 30, 1)
#define                                 MolReader_Hash_get_nth31(s)                     mol_slice_by_offset(s, 31, 1)
#define                                 MolReader_String_verify(s, c)                   mol_fixvec_verify(s, 1)
#define                                 MolReader_String_length(s)                      mol_fixvec_length(s)
#define                                 MolReader_String_get(s, i)                      mol_fixvec_slice_by_index(s, 1, i)
#define                                 MolReader_String_raw_bytes(s)                   mol_fixvec_slice_raw_bytes(s)
MOLECULE_API_DECORATOR  mol_errno       MolReader_StringOpt_verify                      (const mol_seg_t*, bool);
#define                                 MolReader_StringOpt_is_none(s)                  mol_option_is_none(s)
MOLECULE_API_DECORATOR  mol_errno       MolReader_Flag_0_verify                         (const mol_seg_t*, bool);
#define                                 MolReader_Flag_0_actual_field_count(s)          mol_table_actual_field_count(s)
#define                                 MolReader_Flag_0_has_extra_fields(s)            mol_table_has_extra_fields(s, 1)
#define                                 MolReader_Flag_0_get_project_id(s)              mol_table_slice_by_index(s, 0)
MOLECULE_API_DECORATOR  mol_errno       MolReader_Flag_1_verify                         (const mol_seg_t*, bool);
#define                                 MolReader_Flag_1_actual_field_count(s)          mol_table_actual_field_count(s)
#define                                 MolReader_Flag_1_has_extra_fields(s)            mol_table_has_extra_fields(s, 1)
#define                                 MolReader_Flag_1_get_project_id(s)              mol_table_slice_by_index(s, 0)
MOLECULE_API_DECORATOR  mol_errno       MolReader_Flag_2_verify                         (const mol_seg_t*, bool);
#define                                 MolReader_Flag_2_actual_field_count(s)          mol_table_actual_field_count(s)
#define                                 MolReader_Flag_2_has_extra_fields(s)            mol_table_has_extra_fields(s, 3)
#define                                 MolReader_Flag_2_get_function_call(s)           mol_table_slice_by_index(s, 0)
#define                                 MolReader_Flag_2_get_caller_lockscript(s)       mol_table_slice_by_index(s, 1)
#define                                 MolReader_Flag_2_get_recipient_lockscript(s)    mol_table_slice_by_index(s, 2)

/*
 * Builder APIs
 */

#define                                 MolBuilder_Hash_init(b)                         mol_builder_initialize_fixed_size(b, 32)
#define                                 MolBuilder_Hash_set_nth0(b, p)                  mol_builder_set_byte_by_offset(b, 0, p)
#define                                 MolBuilder_Hash_set_nth1(b, p)                  mol_builder_set_byte_by_offset(b, 1, p)
#define                                 MolBuilder_Hash_set_nth2(b, p)                  mol_builder_set_byte_by_offset(b, 2, p)
#define                                 MolBuilder_Hash_set_nth3(b, p)                  mol_builder_set_byte_by_offset(b, 3, p)
#define                                 MolBuilder_Hash_set_nth4(b, p)                  mol_builder_set_byte_by_offset(b, 4, p)
#define                                 MolBuilder_Hash_set_nth5(b, p)                  mol_builder_set_byte_by_offset(b, 5, p)
#define                                 MolBuilder_Hash_set_nth6(b, p)                  mol_builder_set_byte_by_offset(b, 6, p)
#define                                 MolBuilder_Hash_set_nth7(b, p)                  mol_builder_set_byte_by_offset(b, 7, p)
#define                                 MolBuilder_Hash_set_nth8(b, p)                  mol_builder_set_byte_by_offset(b, 8, p)
#define                                 MolBuilder_Hash_set_nth9(b, p)                  mol_builder_set_byte_by_offset(b, 9, p)
#define                                 MolBuilder_Hash_set_nth10(b, p)                 mol_builder_set_byte_by_offset(b, 10, p)
#define                                 MolBuilder_Hash_set_nth11(b, p)                 mol_builder_set_byte_by_offset(b, 11, p)
#define                                 MolBuilder_Hash_set_nth12(b, p)                 mol_builder_set_byte_by_offset(b, 12, p)
#define                                 MolBuilder_Hash_set_nth13(b, p)                 mol_builder_set_byte_by_offset(b, 13, p)
#define                                 MolBuilder_Hash_set_nth14(b, p)                 mol_builder_set_byte_by_offset(b, 14, p)
#define                                 MolBuilder_Hash_set_nth15(b, p)                 mol_builder_set_byte_by_offset(b, 15, p)
#define                                 MolBuilder_Hash_set_nth16(b, p)                 mol_builder_set_byte_by_offset(b, 16, p)
#define                                 MolBuilder_Hash_set_nth17(b, p)                 mol_builder_set_byte_by_offset(b, 17, p)
#define                                 MolBuilder_Hash_set_nth18(b, p)                 mol_builder_set_byte_by_offset(b, 18, p)
#define                                 MolBuilder_Hash_set_nth19(b, p)                 mol_builder_set_byte_by_offset(b, 19, p)
#define                                 MolBuilder_Hash_set_nth20(b, p)                 mol_builder_set_byte_by_offset(b, 20, p)
#define                                 MolBuilder_Hash_set_nth21(b, p)                 mol_builder_set_byte_by_offset(b, 21, p)
#define                                 MolBuilder_Hash_set_nth22(b, p)                 mol_builder_set_byte_by_offset(b, 22, p)
#define                                 MolBuilder_Hash_set_nth23(b, p)                 mol_builder_set_byte_by_offset(b, 23, p)
#define                                 MolBuilder_Hash_set_nth24(b, p)                 mol_builder_set_byte_by_offset(b, 24, p)
#define                                 MolBuilder_Hash_set_nth25(b, p)                 mol_builder_set_byte_by_offset(b, 25, p)
#define                                 MolBuilder_Hash_set_nth26(b, p)                 mol_builder_set_byte_by_offset(b, 26, p)
#define                                 MolBuilder_Hash_set_nth27(b, p)                 mol_builder_set_byte_by_offset(b, 27, p)
#define                                 MolBuilder_Hash_set_nth28(b, p)                 mol_builder_set_byte_by_offset(b, 28, p)
#define                                 MolBuilder_Hash_set_nth29(b, p)                 mol_builder_set_byte_by_offset(b, 29, p)
#define                                 MolBuilder_Hash_set_nth30(b, p)                 mol_builder_set_byte_by_offset(b, 30, p)
#define                                 MolBuilder_Hash_set_nth31(b, p)                 mol_builder_set_byte_by_offset(b, 31, p)
#define                                 MolBuilder_Hash_build(b)                        mol_builder_finalize_simple(b)
#define                                 MolBuilder_Hash_clear(b)                        mol_builder_discard(b)
#define                                 MolBuilder_String_init(b)                       mol_fixvec_builder_initialize(b, 16)
#define                                 MolBuilder_String_push(b, p)                    mol_fixvec_builder_push_byte(b, p)
#define                                 MolBuilder_String_build(b)                      mol_fixvec_builder_finalize(b)
#define                                 MolBuilder_String_clear(b)                      mol_builder_discard(b)
#define                                 MolBuilder_StringOpt_init(b)                    mol_builder_initialize_fixed_size(b, 0)
#define                                 MolBuilder_StringOpt_set(b, p, l)               mol_option_builder_set(b, p, l)
#define                                 MolBuilder_StringOpt_build(b)                   mol_builder_finalize_simple(b)
#define                                 MolBuilder_StringOpt_clear(b)                   mol_builder_discard(b)
#define                                 MolBuilder_Flag_0_init(b)                       mol_table_builder_initialize(b, 256, 1)
#define                                 MolBuilder_Flag_0_set_project_id(b, p, l)       mol_table_builder_add(b, 0, p, l)
MOLECULE_API_DECORATOR  mol_seg_res_t   MolBuilder_Flag_0_build                         (mol_builder_t);
#define                                 MolBuilder_Flag_0_clear(b)                      mol_builder_discard(b)
#define                                 MolBuilder_Flag_1_init(b)                       mol_table_builder_initialize(b, 256, 1)
#define                                 MolBuilder_Flag_1_set_project_id(b, p, l)       mol_table_builder_add(b, 0, p, l)
MOLECULE_API_DECORATOR  mol_seg_res_t   MolBuilder_Flag_1_build                         (mol_builder_t);
#define                                 MolBuilder_Flag_1_clear(b)                      mol_builder_discard(b)
#define                                 MolBuilder_Flag_2_init(b)                       mol_table_builder_initialize(b, 128, 3)
#define                                 MolBuilder_Flag_2_set_function_call(b, p, l)    mol_table_builder_add(b, 0, p, l)
#define                                 MolBuilder_Flag_2_set_caller_lockscript(b, p, l) mol_table_builder_add(b, 1, p, l)
#define                                 MolBuilder_Flag_2_set_recipient_lockscript(b, p, l) mol_table_builder_add(b, 2, p, l)
MOLECULE_API_DECORATOR  mol_seg_res_t   MolBuilder_Flag_2_build                         (mol_builder_t);
#define                                 MolBuilder_Flag_2_clear(b)                      mol_builder_discard(b)

/*
 * Default Value
 */

#define ____ 0x00

MOLECULE_API_DECORATOR const uint8_t MolDefault_Hash[32]         =  {
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_String[4]        =  {____, ____, ____, ____};
MOLECULE_API_DECORATOR const uint8_t MolDefault_StringOpt[0]     =  {};
MOLECULE_API_DECORATOR const uint8_t MolDefault_Flag_0[40]       =  {
    0x28, ____, ____, ____, 0x08, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_Flag_1[40]       =  {
    0x28, ____, ____, ____, 0x08, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_Flag_2[24]       =  {
    0x18, ____, ____, ____, 0x10, ____, ____, ____, 0x14, ____, ____, ____,
    0x18, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
};

#undef ____

/*
 * Reader Functions
 */

MOLECULE_API_DECORATOR mol_errno MolReader_StringOpt_verify (const mol_seg_t *input, bool compatible) {
    if (input->size != 0) {
        return MolReader_String_verify(input, compatible);
    } else {
        return MOL_OK;
    }
}
MOLECULE_API_DECORATOR mol_errno MolReader_Flag_0_verify (const mol_seg_t *input, bool compatible) {
    if (input->size < MOL_NUM_T_SIZE) {
        return MOL_ERR_HEADER;
    }
    uint8_t *ptr = input->ptr;
    mol_num_t total_size = mol_unpack_number(ptr);
    if (input->size != total_size) {
        return MOL_ERR_TOTAL_SIZE;
    }
    if (input->size < MOL_NUM_T_SIZE * 2) {
        return MOL_ERR_HEADER;
    }
    ptr += MOL_NUM_T_SIZE;
    mol_num_t offset = mol_unpack_number(ptr);
    if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE*2) {
        return MOL_ERR_OFFSET;
    }
    mol_num_t field_count = offset / 4 - 1;
    if (field_count < 1) {
        return MOL_ERR_FIELD_COUNT;
    } else if (!compatible && field_count > 1) {
        return MOL_ERR_FIELD_COUNT;
    }
    if (input->size < MOL_NUM_T_SIZE*(field_count+1)){
        return MOL_ERR_HEADER;
    }
    mol_num_t offsets[field_count+1];
    offsets[0] = offset;
    for (mol_num_t i=1; i<field_count; i++) {
        ptr += MOL_NUM_T_SIZE;
        offsets[i] = mol_unpack_number(ptr);
        if (offsets[i-1] > offsets[i]) {
            return MOL_ERR_OFFSET;
        }
    }
    if (offsets[field_count-1] > total_size) {
        return MOL_ERR_OFFSET;
    }
    offsets[field_count] = total_size;
        mol_seg_t inner;
        mol_errno errno;
        inner.ptr = input->ptr + offsets[0];
        inner.size = offsets[1] - offsets[0];
        errno = MolReader_Hash_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
    return MOL_OK;
}
MOLECULE_API_DECORATOR mol_errno MolReader_Flag_1_verify (const mol_seg_t *input, bool compatible) {
    if (input->size < MOL_NUM_T_SIZE) {
        return MOL_ERR_HEADER;
    }
    uint8_t *ptr = input->ptr;
    mol_num_t total_size = mol_unpack_number(ptr);
    if (input->size != total_size) {
        return MOL_ERR_TOTAL_SIZE;
    }
    if (input->size < MOL_NUM_T_SIZE * 2) {
        return MOL_ERR_HEADER;
    }
    ptr += MOL_NUM_T_SIZE;
    mol_num_t offset = mol_unpack_number(ptr);
    if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE*2) {
        return MOL_ERR_OFFSET;
    }
    mol_num_t field_count = offset / 4 - 1;
    if (field_count < 1) {
        return MOL_ERR_FIELD_COUNT;
    } else if (!compatible && field_count > 1) {
        return MOL_ERR_FIELD_COUNT;
    }
    if (input->size < MOL_NUM_T_SIZE*(field_count+1)){
        return MOL_ERR_HEADER;
    }
    mol_num_t offsets[field_count+1];
    offsets[0] = offset;
    for (mol_num_t i=1; i<field_count; i++) {
        ptr += MOL_NUM_T_SIZE;
        offsets[i] = mol_unpack_number(ptr);
        if (offsets[i-1] > offsets[i]) {
            return MOL_ERR_OFFSET;
        }
    }
    if (offsets[field_count-1] > total_size) {
        return MOL_ERR_OFFSET;
    }
    offsets[field_count] = total_size;
        mol_seg_t inner;
        mol_errno errno;
        inner.ptr = input->ptr + offsets[0];
        inner.size = offsets[1] - offsets[0];
        errno = MolReader_Hash_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
    return MOL_OK;
}
MOLECULE_API_DECORATOR mol_errno MolReader_Flag_2_verify (const mol_seg_t *input, bool compatible) {
    if (input->size < MOL_NUM_T_SIZE) {
        return MOL_ERR_HEADER;
    }
    uint8_t *ptr = input->ptr;
    mol_num_t total_size = mol_unpack_number(ptr);
    if (input->size != total_size) {
        return MOL_ERR_TOTAL_SIZE;
    }
    if (input->size < MOL_NUM_T_SIZE * 2) {
        return MOL_ERR_HEADER;
    }
    ptr += MOL_NUM_T_SIZE;
    mol_num_t offset = mol_unpack_number(ptr);
    if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE*2) {
        return MOL_ERR_OFFSET;
    }
    mol_num_t field_count = offset / 4 - 1;
    if (field_count < 3) {
        return MOL_ERR_FIELD_COUNT;
    } else if (!compatible && field_count > 3) {
        return MOL_ERR_FIELD_COUNT;
    }
    if (input->size < MOL_NUM_T_SIZE*(field_count+1)){
        return MOL_ERR_HEADER;
    }
    mol_num_t offsets[field_count+1];
    offsets[0] = offset;
    for (mol_num_t i=1; i<field_count; i++) {
        ptr += MOL_NUM_T_SIZE;
        offsets[i] = mol_unpack_number(ptr);
        if (offsets[i-1] > offsets[i]) {
            return MOL_ERR_OFFSET;
        }
    }
    if (offsets[field_count-1] > total_size) {
        return MOL_ERR_OFFSET;
    }
    offsets[field_count] = total_size;
        mol_seg_t inner;
        mol_errno errno;
        inner.ptr = input->ptr + offsets[0];
        inner.size = offsets[1] - offsets[0];
        errno = MolReader_String_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
        inner.ptr = input->ptr + offsets[1];
        inner.size = offsets[2] - offsets[1];
        errno = MolReader_String_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
        inner.ptr = input->ptr + offsets[2];
        inner.size = offsets[3] - offsets[2];
        errno = MolReader_StringOpt_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
    return MOL_OK;
}

/*
 * Builder Functions
 */

MOLECULE_API_DECORATOR mol_seg_res_t MolBuilder_Flag_0_build (mol_builder_t builder) {
    mol_seg_res_t res;
    res.errno = MOL_OK;
    mol_num_t offset = 8;
    mol_num_t len;
    res.seg.size = offset;
    len = builder.number_ptr[1];
    res.seg.size += len == 0 ? 32 : len;
    res.seg.ptr = (uint8_t*)malloc(res.seg.size);
    uint8_t *dst = res.seg.ptr;
    mol_pack_number(dst, &res.seg.size);
    dst += MOL_NUM_T_SIZE;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[1];
    offset += len == 0 ? 32 : len;
    uint8_t *src = builder.data_ptr;
    len = builder.number_ptr[1];
    if (len == 0) {
        len = 32;
        memcpy(dst, &MolDefault_Hash, len);
    } else {
        mol_num_t of = builder.number_ptr[0];
        memcpy(dst, src+of, len);
    }
    dst += len;
    mol_builder_discard(builder);
    return res;
}
MOLECULE_API_DECORATOR mol_seg_res_t MolBuilder_Flag_1_build (mol_builder_t builder) {
    mol_seg_res_t res;
    res.errno = MOL_OK;
    mol_num_t offset = 8;
    mol_num_t len;
    res.seg.size = offset;
    len = builder.number_ptr[1];
    res.seg.size += len == 0 ? 32 : len;
    res.seg.ptr = (uint8_t*)malloc(res.seg.size);
    uint8_t *dst = res.seg.ptr;
    mol_pack_number(dst, &res.seg.size);
    dst += MOL_NUM_T_SIZE;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[1];
    offset += len == 0 ? 32 : len;
    uint8_t *src = builder.data_ptr;
    len = builder.number_ptr[1];
    if (len == 0) {
        len = 32;
        memcpy(dst, &MolDefault_Hash, len);
    } else {
        mol_num_t of = builder.number_ptr[0];
        memcpy(dst, src+of, len);
    }
    dst += len;
    mol_builder_discard(builder);
    return res;
}
MOLECULE_API_DECORATOR mol_seg_res_t MolBuilder_Flag_2_build (mol_builder_t builder) {
    mol_seg_res_t res;
    res.errno = MOL_OK;
    mol_num_t offset = 16;
    mol_num_t len;
    res.seg.size = offset;
    len = builder.number_ptr[1];
    res.seg.size += len == 0 ? 4 : len;
    len = builder.number_ptr[3];
    res.seg.size += len == 0 ? 4 : len;
    len = builder.number_ptr[5];
    res.seg.size += len == 0 ? 0 : len;
    res.seg.ptr = (uint8_t*)malloc(res.seg.size);
    uint8_t *dst = res.seg.ptr;
    mol_pack_number(dst, &res.seg.size);
    dst += MOL_NUM_T_SIZE;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[1];
    offset += len == 0 ? 4 : len;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[3];
    offset += len == 0 ? 4 : len;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[5];
    offset += len == 0 ? 0 : len;
    uint8_t *src = builder.data_ptr;
    len = builder.number_ptr[1];
    if (len == 0) {
        len = 4;
        memcpy(dst, &MolDefault_String, len);
    } else {
        mol_num_t of = builder.number_ptr[0];
        memcpy(dst, src+of, len);
    }
    dst += len;
    len = builder.number_ptr[3];
    if (len == 0) {
        len = 4;
        memcpy(dst, &MolDefault_String, len);
    } else {
        mol_num_t of = builder.number_ptr[2];
        memcpy(dst, src+of, len);
    }
    dst += len;
    len = builder.number_ptr[5];
    if (len == 0) {
        len = 0;
        memcpy(dst, &MolDefault_StringOpt, len);
    } else {
        mol_num_t of = builder.number_ptr[4];
        memcpy(dst, src+of, len);
    }
    dst += len;
    mol_builder_discard(builder);
    return res;
}

#ifdef __DEFINE_MOLECULE_API_DECORATOR_PROTOCOL
#undef MOLECULE_API_DECORATOR
#undef __DEFINE_MOLECULE_API_DECORATOR_PROTOCOL
#endif /* __DEFINE_MOLECULE_API_DECORATOR_PROTOCOL */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROTOCOL_H */
