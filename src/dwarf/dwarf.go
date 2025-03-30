package dwarf

import (
	binutil "branch-walker/binutil"
	elf "branch-walker/elf"
	logger "branch-walker/logger"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"
)

// DWARF format(size)
const (
	// DWARF Format size spesicified by header unit_length (initial length)
	// less than 0xFFFF00 is 32-bit DWARF format
	DWARF_32BIT_FORMAT = 0x01
	DWARF_64BIT_FORMAT = 0x02
)

// DWARF5 P199 7.5.1 Unit Headers
const (
	DW_UT_compile       = 0x01
	DW_UT_type          = 0x02
	DW_UT_partial       = 0x03
	DW_UT_skeleton      = 0x04
	DW_UT_split_compile = 0x05
	DW_UT_split_type    = 0x06
	DW_UT_lo_user       = 0x80
	DW_UT_hi_user       = 0xff
)

const (
	DW_TAG_array_type               = 0x01
	DW_TAG_class_type               = 0x02
	DW_TAG_entry_point              = 0x03
	DW_TAG_enumeration_type         = 0x04
	DW_TAG_formal_parameter         = 0x05
	DW_TAG_imported_declaration     = 0x08
	DW_TAG_label                    = 0x0a
	DW_TAG_lexical_block            = 0x0b
	DW_TAG_member                   = 0x0d
	DW_TAG_pointer_type             = 0x0f
	DW_TAG_reference_type           = 0x10
	DW_TAG_compile_unit             = 0x11
	DW_TAG_string_type              = 0x12
	DW_TAG_structure_type           = 0x13
	DW_TAG_subroutine_type          = 0x15
	DW_TAG_typedef                  = 0x16
	DW_TAG_union_type               = 0x17
	DW_TAG_unspecified_parameters   = 0x18
	DW_TAG_variant                  = 0x19
	DW_TAG_common_block             = 0x1a
	DW_TAG_common_inclusion         = 0x1b
	DW_TAG_inheritance              = 0x1c
	DW_TAG_inlined_subroutine       = 0x1d
	DW_TAG_module                   = 0x1e
	DW_TAG_ptr_to_member_type       = 0x1f
	DW_TAG_set_type                 = 0x20
	DW_TAG_subrange_type            = 0x21
	DW_TAG_with_stmt                = 0x22
	DW_TAG_access_declaration       = 0x23
	DW_TAG_base_type                = 0x24
	DW_TAG_catch_block              = 0x25
	DW_TAG_const_type               = 0x26
	DW_TAG_constant                 = 0x27
	DW_TAG_enumerator               = 0x28
	DW_TAG_file_type                = 0x29
	DW_TAG_friend                   = 0x2a
	DW_TAG_namelist                 = 0x2b
	DW_TAG_namelist_item            = 0x2c
	DW_TAG_packed_type              = 0x2d
	DW_TAG_subprogram               = 0x2e
	DW_TAG_template_type_parameter  = 0x2f
	DW_TAG_template_value_parameter = 0x30
	DW_TAG_thrown_type              = 0x31
	DW_TAG_try_block                = 0x32
	DW_TAG_variant_part             = 0x33
	DW_TAG_variable                 = 0x34
	DW_TAG_volatile_type            = 0x35
	DW_TAG_dwarf_procedure          = 0x36
	DW_TAG_restrict_type            = 0x37
	DW_TAG_interface_type           = 0x38
	DW_TAG_namespace                = 0x39
	DW_TAG_imported_module          = 0x3a
	DW_TAG_unspecified_type         = 0x3b
	DW_TAG_partial_unit             = 0x3c
	DW_TAG_imported_unit            = 0x3d
	DW_TAG_condition                = 0x3f
	DW_TAG_shared_type              = 0x40
	DW_TAG_type_unit                = 0x41
	DW_TAG_rvalue_reference_type    = 0x42
	DW_TAG_template_alias           = 0x43

	DW_TAG_lo_user = 0x4080
	DW_TAG_hi_user = 0xffff
)

// ============================================================================
// Attribute Code define
// ============================================================================
const (
	DW_AT_sibling              = 0x01   // reference
	DW_AT_location             = 0x02   // exprloc, loclistptr
	DW_AT_name                 = 0x03   // string
	DW_AT_ordering             = 0x09   // constant
	DW_AT_byte_size            = 0x0b   // constant, exprloc, reference
	DW_AT_bit_offset           = 0x0c   // constant, exprloc, reference
	DW_AT_bit_size             = 0x0d   // constant, exprloc, reference
	DW_AT_stmt_list            = 0x10   // lineptr
	DW_AT_low_pc               = 0x11   // address
	DW_AT_high_pc              = 0x12   // address, constant
	DW_AT_language             = 0x13   // constant
	DW_AT_discr                = 0x15   // reference
	DW_AT_discr_value          = 0x16   // constant
	DW_AT_visibility           = 0x17   // constant
	DW_AT_import               = 0x18   // reference
	DW_AT_string_length        = 0x19   // exprloc, loclistptr
	DW_AT_common_reference     = 0x1a   // reference
	DW_AT_comp_dir             = 0x1b   // string
	DW_AT_const_value          = 0x1c   // block, constant, string
	DW_AT_containing_type      = 0x1d   // reference
	DW_AT_default_value        = 0x1e   // reference
	DW_AT_inline               = 0x20   // constant
	DW_AT_is_optional          = 0x21   // flag
	DW_AT_lower_bound          = 0x22   // constant, exprloc, reference
	DW_AT_producer             = 0x25   // string
	DW_AT_prototyped           = 0x27   // flag
	DW_AT_return_addr          = 0x2a   // exprloc, loclistptr
	DW_AT_start_scope          = 0x2c   // Constant, rangelistptr
	DW_AT_bit_stride           = 0x2e   // constant, exprloc, reference
	DW_AT_upper_bound          = 0x2f   // constant, exprloc, reference
	DW_AT_abstract_origin      = 0x31   // reference
	DW_AT_accessibility        = 0x32   // constant
	DW_AT_address_class        = 0x33   // constant
	DW_AT_artificial           = 0x34   // flag
	DW_AT_base_types           = 0x35   // reference
	DW_AT_calling_convention   = 0x36   // constant
	DW_AT_count                = 0x37   // constant, exprloc, reference
	DW_AT_data_member_location = 0x38   // constant, exprloc, loclistptr
	DW_AT_decl_column          = 0x39   // constant
	DW_AT_decl_file            = 0x3a   // constant
	DW_AT_decl_line            = 0x3b   // constant
	DW_AT_declaration          = 0x3c   // flag
	DW_AT_discr_list           = 0x3d   // block
	DW_AT_encoding             = 0x3e   // constant
	DW_AT_external             = 0x3f   // flag
	DW_AT_frame_base           = 0x40   // exprloc, loclistptr
	DW_AT_friend               = 0x41   // reference
	DW_AT_identifier_case      = 0x42   // constant
	DW_AT_macro_info           = 0x43   // macptr
	DW_AT_namelist_item        = 0x44   // reference
	DW_AT_priority             = 0x45   // reference
	DW_AT_segment              = 0x46   // exprloc, loclistptr
	DW_AT_specification        = 0x47   // reference
	DW_AT_static_link          = 0x48   // exprloc, loclistptr
	DW_AT_type                 = 0x49   // reference
	DW_AT_use_location         = 0x4a   // exprloc, loclistptr
	DW_AT_variable_parameter   = 0x4b   // flag
	DW_AT_virtuality           = 0x4c   // constant
	DW_AT_vtable_elem_location = 0x4d   // exprloc, loclistptr
	DW_AT_allocated            = 0x4e   // constant, exprloc, reference
	DW_AT_associated           = 0x4f   // constant, exprloc, reference
	DW_AT_data_location        = 0x50   // exprloc
	DW_AT_byte_stride          = 0x51   // constant, exprloc, reference
	DW_AT_entry_pc             = 0x52   // address
	DW_AT_use_UTF8             = 0x53   // flag
	DW_AT_extension            = 0x54   // reference
	DW_AT_ranges               = 0x55   // rangelistptr
	DW_AT_trampoline           = 0x56   // address, flag, reference, string
	DW_AT_call_column          = 0x57   // constant
	DW_AT_call_file            = 0x58   // constant
	DW_AT_call_line            = 0x59   // constant
	DW_AT_description          = 0x5a   // string
	DW_AT_binary_scale         = 0x5b   // constant
	DW_AT_decimal_scale        = 0x5c   // constant
	DW_AT_small                = 0x5d   // reference
	DW_AT_decimal_sign         = 0x5e   // constant
	DW_AT_digit_count          = 0x5f   // constant
	DW_AT_picture_string       = 0x60   // string
	DW_AT_mutable              = 0x61   // flag
	DW_AT_threads_scaled       = 0x62   // flag
	DW_AT_explicit             = 0x63   // flag
	DW_AT_object_pointer       = 0x64   // reference
	DW_AT_endianity            = 0x65   // constant
	DW_AT_elemental            = 0x66   // flag
	DW_AT_pure                 = 0x67   // flag
	DW_AT_recursive            = 0x68   // flag
	DW_AT_signature            = 0x69   // reference
	DW_AT_main_subprogram      = 0x6a   // flag
	DW_AT_data_bit_offset      = 0x6b   // constant
	DW_AT_const_expr           = 0x6c   // flag
	DW_AT_enum_class           = 0x6d   // flag
	DW_AT_linkage_name         = 0x6e   // string
	DW_AT_lo_user              = 0x2000 // ---

	// see https://sourceware.org/elfutils/DwarfExtensions
	DW_AT_MIPS_linkage_name = 0x2007
	// GNU Extensions
	sf_names                       = 0x2101
	src_info                       = 0x2102
	mac_info                       = 0x2103
	src_coords                     = 0x2104
	body_begin                     = 0x2105
	body_end                       = 0x2106
	GNU_vector                     = 0x2107
	GNU_odr_signature              = 0x210f
	GNU_template_name              = 0x2110
	GNU_call_site_value            = 0x2111
	GNU_call_site_data_value       = 0x2112
	GNU_call_site_target           = 0x2113
	GNU_call_site_target_clobbered = 0x2114
	GNU_tail_call                  = 0x2115
	GNU_all_tail_call_sites        = 0x2116
	GNU_all_call_sites             = 0x2117
	GNU_all_source_call_sites      = 0x2118
	GNU_macros                     = 0x2119
	GNU_deleted                    = 0x211a
	GNU_dwo_name                   = 0x2130
	GNU_dwo_id                     = 0x2131
	GNU_ranges_base                = 0x2132
	GNU_addr_base                  = 0x2133
	GNU_pubnames                   = 0x2134
	GNU_pubtypes                   = 0x2135
	GNU_discriminator              = 0x2136
	GNU_locviews                   = 0x2137
	GNU_entry_view                 = 0x2138

	DW_AT_hi_user = 0x3fff // ---
)

// ============================================================================
// Form Code define
// ============================================================================
const (
	DW_FORM_addr           = 0x01 // address
	DW_FORM_block2         = 0x03 // block
	DW_FORM_block4         = 0x04 // block
	DW_FORM_data2          = 0x05 // constant
	DW_FORM_data4          = 0x06 // constant
	DW_FORM_data8          = 0x07 // constant
	DW_FORM_string         = 0x08 // string
	DW_FORM_block          = 0x09 // block
	DW_FORM_block1         = 0x0a // block
	DW_FORM_data1          = 0x0b // constant
	DW_FORM_flag           = 0x0c // flag
	DW_FORM_sdata          = 0x0d // constant
	DW_FORM_strp           = 0x0e // string
	DW_FORM_udata          = 0x0f // constant
	DW_FORM_ref_addr       = 0x10 // reference
	DW_FORM_ref1           = 0x11 // reference
	DW_FORM_ref2           = 0x12 // reference
	DW_FORM_ref4           = 0x13 // reference
	DW_FORM_ref8           = 0x14 // reference
	DW_FORM_ref_udata      = 0x15 // reference
	DW_FORM_indirect       = 0x16 // (see Section 7.5.3)
	DW_FORM_sec_offset     = 0x17 // lineptr, loclistptr, macptr, rangelistptr
	DW_FORM_exprloc        = 0x18 // exprloc
	DW_FORM_flag_present   = 0x19 // flag
	DW_FORM_strx           = 0x1a // string(DWARF5～)
	DW_FORM_addrx          = 0x1b // addresss(DWARF5～)
	DW_FORM_ref_sup4       = 0x1c // reference(DWARF5～)
	DW_FORM_strp_sup       = 0x1d // string(DWARF5～)
	DW_FORM_data16         = 0x1e // constant(DWARF5～)
	DW_FORM_line_strp      = 0x1f // string(DWARF5～)
	DW_FORM_ref_sig8       = 0x20 // reference
	DW_FORM_implicit_const = 0x21 // constant
	DW_FORM_loclistx       = 0x22 // loclist
	DW_FORM_rnglistx       = 0x23 // rnglist
	DW_FORM_ref_sup8       = 0x24 // reference
	DW_FORM_strx1          = 0x25 // string
	DW_FORM_strx2          = 0x26 // string
	DW_FORM_strx3          = 0x27 // string
	DW_FORM_strx4          = 0x28 // string
	DW_FORM_addrx1         = 0x29 // address
	DW_FORM_addrx2         = 0x2a // address
	DW_FORM_addrx3         = 0x2b // address
	DW_FORM_addrx4         = 0x2c // address
)

var TagNameMap = map[uint64]string{
	DW_TAG_array_type:               "TAG_array_type",
	DW_TAG_class_type:               "TAG_class_type",
	DW_TAG_entry_point:              "TAG_entry_point",
	DW_TAG_enumeration_type:         "TAG_enumeration_type",
	DW_TAG_formal_parameter:         "TAG_formal_parameter",
	DW_TAG_imported_declaration:     "DW_TAG_imported_declaration",
	DW_TAG_label:                    "DW_TAG_label",
	DW_TAG_lexical_block:            "DW_TAG_lexical_block",
	DW_TAG_member:                   "DW_TAG_member",
	DW_TAG_pointer_type:             "DW_TAG_pointer_type",
	DW_TAG_reference_type:           "DW_TAG_reference_type",
	DW_TAG_compile_unit:             "DW_TAG_compile_unit",
	DW_TAG_string_type:              "DW_TAG_string_type",
	DW_TAG_structure_type:           "DW_TAG_structure_type",
	DW_TAG_subroutine_type:          "DW_TAG_subroutine_type",
	DW_TAG_typedef:                  "DW_TAG_typedef",
	DW_TAG_union_type:               "DW_TAG_union_type",
	DW_TAG_unspecified_parameters:   "DW_TAG_unspecified_parameters",
	DW_TAG_variant:                  "DW_TAG_variant",
	DW_TAG_common_block:             "DW_TAG_common_block",
	DW_TAG_common_inclusion:         "DW_TAG_common_inclusion",
	DW_TAG_inheritance:              "DW_TAG_inheritance",
	DW_TAG_inlined_subroutine:       "DW_TAG_inlined_subroutine",
	DW_TAG_module:                   "DW_TAG_module",
	DW_TAG_ptr_to_member_type:       "DW_TAG_ptr_to_member_type",
	DW_TAG_set_type:                 "DW_TAG_set_type",
	DW_TAG_subrange_type:            "DW_TAG_subrange_type",
	DW_TAG_with_stmt:                "DW_TAG_with_stmt",
	DW_TAG_access_declaration:       "DW_TAG_access_declaration",
	DW_TAG_base_type:                "DW_TAG_base_type",
	DW_TAG_catch_block:              "DW_TAG_catch_block",
	DW_TAG_const_type:               "DW_TAG_const_type",
	DW_TAG_constant:                 "DW_TAG_constant",
	DW_TAG_enumerator:               "DW_TAG_enumerator",
	DW_TAG_file_type:                "DW_TAG_file_type",
	DW_TAG_friend:                   "DW_TAG_friend",
	DW_TAG_namelist:                 "DW_TAG_namelist",
	DW_TAG_namelist_item:            "DW_TAG_namelist_item",
	DW_TAG_packed_type:              "DW_TAG_packed_type",
	DW_TAG_subprogram:               "DW_TAG_subprogram",
	DW_TAG_template_type_parameter:  "DW_TAG_template_type_parameter",
	DW_TAG_template_value_parameter: "DW_TAG_template_value_parameter",
	DW_TAG_thrown_type:              "DW_TAG_thrown_type",
	DW_TAG_try_block:                "DW_TAG_try_block",
	DW_TAG_variant_part:             "DW_TAG_variant_part",
	DW_TAG_variable:                 "DW_TAG_variable",
	DW_TAG_volatile_type:            "DW_TAG_volatile_type",
	DW_TAG_dwarf_procedure:          "DW_TAG_dwarf_procedure",
	DW_TAG_restrict_type:            "DW_TAG_restrict_type",
	DW_TAG_interface_type:           "DW_TAG_interface_type",
	DW_TAG_namespace:                "DW_TAG_namespace",
	DW_TAG_imported_module:          "DW_TAG_imported_module",
	DW_TAG_unspecified_type:         "DW_TAG_unspecified_type",
	DW_TAG_partial_unit:             "DW_TAG_partial_unit",
	DW_TAG_imported_unit:            "DW_TAG_imported_unit",
	DW_TAG_condition:                "DW_TAG_condition",
	DW_TAG_shared_type:              "DW_TAG_shared_type",
	DW_TAG_type_unit:                "DW_TAG_type_unit",
	DW_TAG_rvalue_reference_type:    "DW_TAG_rvalue_reference_type",
	DW_TAG_template_alias:           "DW_TAG_template_alias",
	DW_TAG_lo_user:                  "TAG_lo_user",
	DW_TAG_hi_user:                  "TAG_hi_user",
}

var AttrNameMap = map[uint64]string{
	DW_AT_sibling:              "DW_AT_sibling",
	DW_AT_location:             "DW_AT_location",
	DW_AT_name:                 "DW_AT_name",
	DW_AT_ordering:             "DW_AT_ordering",
	DW_AT_byte_size:            "DW_AT_byte_size",
	DW_AT_bit_offset:           "DW_AT_bit_offset",
	DW_AT_bit_size:             "DW_AT_bit_size",
	DW_AT_stmt_list:            "DW_AT_stmt_list",
	DW_AT_low_pc:               "DW_AT_low_pc",
	DW_AT_high_pc:              "DW_AT_high_pc",
	DW_AT_language:             "DW_AT_language",
	DW_AT_discr:                "DW_AT_discr",
	DW_AT_discr_value:          "DW_AT_discr_value",
	DW_AT_visibility:           "DW_AT_visibility",
	DW_AT_import:               "DW_AT_import",
	DW_AT_string_length:        "DW_AT_string_length",
	DW_AT_common_reference:     "DW_AT_common_reference",
	DW_AT_comp_dir:             "DW_AT_comp_dir",
	DW_AT_const_value:          "DW_AT_const_value",
	DW_AT_containing_type:      "DW_AT_containing_type",
	DW_AT_default_value:        "DW_AT_default_value",
	DW_AT_inline:               "DW_AT_inline",
	DW_AT_is_optional:          "DW_AT_is_optional",
	DW_AT_lower_bound:          "DW_AT_lower_bound",
	DW_AT_producer:             "DW_AT_producer",
	DW_AT_prototyped:           "DW_AT_prototyped",
	DW_AT_return_addr:          "DW_AT_return_addr",
	DW_AT_start_scope:          "DW_AT_start_scope",
	DW_AT_bit_stride:           "DW_AT_bit_stride",
	DW_AT_upper_bound:          "DW_AT_upper_bound",
	DW_AT_abstract_origin:      "DW_AT_abstract_origin",
	DW_AT_accessibility:        "DW_AT_accessibility",
	DW_AT_address_class:        "DW_AT_address_class",
	DW_AT_artificial:           "DW_AT_artificial",
	DW_AT_base_types:           "DW_AT_base_types",
	DW_AT_calling_convention:   "DW_AT_calling_convention",
	DW_AT_count:                "DW_AT_count",
	DW_AT_data_member_location: "DW_AT_data_member_location",
	DW_AT_decl_column:          "DW_AT_decl_column",
	DW_AT_decl_file:            "DW_AT_decl_file",
	DW_AT_decl_line:            "DW_AT_decl_line",
	DW_AT_declaration:          "DW_AT_declaration",
	DW_AT_discr_list:           "DW_AT_discr_list",
	DW_AT_encoding:             "DW_AT_encoding",
	DW_AT_external:             "DW_AT_external",
	DW_AT_frame_base:           "DW_AT_frame_base",
	DW_AT_friend:               "DW_AT_friend",
	DW_AT_identifier_case:      "DW_AT_identifier_case",
	DW_AT_macro_info:           "DW_AT_macro_info",
	DW_AT_namelist_item:        "DW_AT_namelist_item",
	DW_AT_priority:             "DW_AT_priority",
	DW_AT_segment:              "DW_AT_segment",
	DW_AT_specification:        "DW_AT_specification",
	DW_AT_static_link:          "DW_AT_static_link",
	DW_AT_type:                 "DW_AT_type",
	DW_AT_use_location:         "DW_AT_use_location",
	DW_AT_variable_parameter:   "DW_AT_variable_parameter",
	DW_AT_virtuality:           "DW_AT_virtuality",
	DW_AT_vtable_elem_location: "DW_AT_vtable_elem_location",
	DW_AT_allocated:            "DW_AT_allocated",
	DW_AT_associated:           "DW_AT_associated",
	DW_AT_data_location:        "DW_AT_data_location",
	DW_AT_byte_stride:          "DW_AT_byte_stride",
	DW_AT_entry_pc:             "DW_AT_entry_pc",
	DW_AT_use_UTF8:             "DW_AT_use_UTF8",
	DW_AT_extension:            "DW_AT_extension",
	DW_AT_ranges:               "DW_AT_ranges",
	DW_AT_trampoline:           "DW_AT_trampoline",
	DW_AT_call_column:          "DW_AT_call_column",
	DW_AT_call_file:            "DW_AT_call_file",
	DW_AT_call_line:            "DW_AT_call_line",
	DW_AT_description:          "DW_AT_description",
	DW_AT_binary_scale:         "DW_AT_binary_scale",
	DW_AT_decimal_scale:        "DW_AT_decimal_scale",
	DW_AT_small:                "DW_AT_small",
	DW_AT_decimal_sign:         "DW_AT_decimal_sign",
	DW_AT_digit_count:          "DW_AT_digit_count",
	DW_AT_picture_string:       "DW_AT_picture_string",
	DW_AT_mutable:              "DW_AT_mutable",
	DW_AT_threads_scaled:       "DW_AT_threads_scaled",
	DW_AT_explicit:             "DW_AT_explicit",
	DW_AT_object_pointer:       "DW_AT_object_pointer",
	DW_AT_endianity:            "DW_AT_endianity",
	DW_AT_elemental:            "DW_AT_elemental",
	DW_AT_pure:                 "DW_AT_pure",
	DW_AT_recursive:            "DW_AT_recursive",
	DW_AT_signature:            "DW_AT_signature",
	DW_AT_main_subprogram:      "DW_AT_main_subprogram",
	DW_AT_data_bit_offset:      "DW_AT_data_bit_offset",
	DW_AT_const_expr:           "DW_AT_const_expr",
	DW_AT_enum_class:           "DW_AT_enum_class",
	DW_AT_linkage_name:         "DW_AT_linkage_name",
	DW_AT_lo_user:              "DW_AT_lo_user",
	DW_AT_hi_user:              "DW_AT_hi_user",
}

var FormNameMap = map[uint64]string{
	DW_FORM_addr:         "DW_FORM_addr",
	DW_FORM_block2:       "DW_FORM_block2",
	DW_FORM_block4:       "DW_FORM_block4",
	DW_FORM_data2:        "DW_FORM_data2",
	DW_FORM_data4:        "DW_FORM_data4",
	DW_FORM_data8:        "DW_FORM_data8",
	DW_FORM_string:       "DW_FORM_string",
	DW_FORM_block:        "DW_FORM_block",
	DW_FORM_block1:       "DW_FORM_block1",
	DW_FORM_data1:        "DW_FORM_data1",
	DW_FORM_flag:         "DW_FORM_flag",
	DW_FORM_sdata:        "DW_FORM_sdata",
	DW_FORM_strp:         "DW_FORM_strp",
	DW_FORM_udata:        "DW_FORM_udata",
	DW_FORM_ref_addr:     "DW_FORM_ref_addr",
	DW_FORM_ref1:         "DW_FORM_ref1",
	DW_FORM_ref2:         "DW_FORM_ref2",
	DW_FORM_ref4:         "DW_FORM_ref4",
	DW_FORM_ref8:         "DW_FORM_ref8",
	DW_FORM_ref_udata:    "DW_FORM_ref_udata",
	DW_FORM_indirect:     "DW_FORM_indirect",
	DW_FORM_sec_offset:   "DW_FORM_sec_offset",
	DW_FORM_exprloc:      "DW_FORM_exprloc",
	DW_FORM_flag_present: "DW_FORM_flag_present",
	DW_FORM_ref_sig8:     "DW_FORM_ref_sig8",
}

const (
	DW_CHILDREN_no  = 0x00
	DW_CHILDREN_yes = 0x01
)

// ============================================================================
// DW_OP
// ============================================================================
const (
	DW_OP_addr                = 0x03
	DW_OP_deref               = 0x06
	DW_OP_const1u             = 0x08
	DW_OP_const1s             = 0x09
	DW_OP_const2u             = 0x0a
	DW_OP_const2s             = 0x0b
	DW_OP_const4u             = 0x0c
	DW_OP_const4s             = 0x0d
	DW_OP_const8u             = 0x0e
	DW_OP_const8s             = 0x0f
	DW_OP_constu              = 0x10
	DW_OP_consts              = 0x11
	DW_OP_dup                 = 0x12
	DW_OP_drop                = 0x13
	DW_OP_over                = 0x14
	DW_OP_pick                = 0x15
	DW_OP_swap                = 0x16
	DW_OP_rot                 = 0x17
	DW_OP_xderef              = 0x18
	DW_OP_abs                 = 0x19
	DW_OP_and                 = 0x1a
	DW_OP_div                 = 0x1b
	DW_OP_minus               = 0x1c
	DW_OP_mod                 = 0x1d
	DW_OP_mul                 = 0x1e
	DW_OP_neg                 = 0x1f
	DW_OP_not                 = 0x20
	DW_OP_or                  = 0x21
	DW_OP_plus                = 0x22
	DW_OP_plus_uconst         = 0x23
	DW_OP_shl                 = 0x24
	DW_OP_shr                 = 0x25
	DW_OP_shra                = 0x26
	DW_OP_xor                 = 0x27
	DW_OP_skip                = 0x2f
	DW_OP_bra                 = 0x28
	DW_OP_eq                  = 0x29
	DW_OP_ge                  = 0x2a
	DW_OP_gt                  = 0x2b
	DW_OP_le                  = 0x2c
	DW_OP_lt                  = 0x2d
	DW_OP_ne                  = 0x2e
	DW_OP_lit0                = 0x30
	DW_OP_lit1                = 0x31
	DW_OP_lit2                = 0x32
	DW_OP_lit3                = 0x33
	DW_OP_lit4                = 0x34
	DW_OP_lit5                = 0x35
	DW_OP_lit6                = 0x36
	DW_OP_lit7                = 0x37
	DW_OP_lit8                = 0x38
	DW_OP_lit9                = 0x39
	DW_OP_lit10               = 0x3A
	DW_OP_lit11               = 0x3B
	DW_OP_lit12               = 0x3C
	DW_OP_lit13               = 0x3D
	DW_OP_lit14               = 0x3E
	DW_OP_lit15               = 0x3F
	DW_OP_lit16               = 0x40
	DW_OP_lit17               = 0x41
	DW_OP_lit18               = 0x42
	DW_OP_lit19               = 0x43
	DW_OP_lit20               = 0x44
	DW_OP_lit21               = 0x45
	DW_OP_lit22               = 0x46
	DW_OP_lit23               = 0x47
	DW_OP_lit24               = 0x48
	DW_OP_lit25               = 0x49
	DW_OP_lit26               = 0x4A
	DW_OP_lit27               = 0x4B
	DW_OP_lit28               = 0x4C
	DW_OP_lit29               = 0x4D
	DW_OP_lit30               = 0x4E
	DW_OP_lit31               = 0x4F
	DW_OP_reg0                = 0x50
	DW_OP_reg1                = 0x51
	DW_OP_reg2                = 0x52
	DW_OP_reg3                = 0x53
	DW_OP_reg4                = 0x54
	DW_OP_reg5                = 0x55
	DW_OP_reg6                = 0x56
	DW_OP_reg7                = 0x57
	DW_OP_reg8                = 0x58
	DW_OP_reg9                = 0x59
	DW_OP_reg10               = 0x5A
	DW_OP_reg11               = 0x5B
	DW_OP_reg12               = 0x5C
	DW_OP_reg13               = 0x5D
	DW_OP_reg14               = 0x5E
	DW_OP_reg15               = 0x5F
	DW_OP_reg16               = 0x60
	DW_OP_reg17               = 0x61
	DW_OP_reg18               = 0x62
	DW_OP_reg19               = 0x63
	DW_OP_reg20               = 0x64
	DW_OP_reg21               = 0x65
	DW_OP_reg22               = 0x66
	DW_OP_reg23               = 0x67
	DW_OP_reg24               = 0x68
	DW_OP_reg25               = 0x69
	DW_OP_reg26               = 0x6A
	DW_OP_reg27               = 0x6B
	DW_OP_reg28               = 0x6C
	DW_OP_reg29               = 0x6D
	DW_OP_reg30               = 0x6E
	DW_OP_reg31               = 0x6f
	DW_OP_breg0               = 0x70
	DW_OP_breg1               = 0x71
	DW_OP_breg2               = 0x72
	DW_OP_breg3               = 0x73
	DW_OP_breg4               = 0x74
	DW_OP_breg5               = 0x75
	DW_OP_breg6               = 0x76
	DW_OP_breg7               = 0x77
	DW_OP_breg8               = 0x78
	DW_OP_breg9               = 0x79
	DW_OP_breg10              = 0x7A
	DW_OP_breg11              = 0x7B
	DW_OP_breg12              = 0x7C
	DW_OP_breg13              = 0x7D
	DW_OP_breg14              = 0x7E
	DW_OP_breg15              = 0x7F
	DW_OP_breg16              = 0x80
	DW_OP_breg17              = 0x81
	DW_OP_breg18              = 0x82
	DW_OP_breg19              = 0x83
	DW_OP_breg20              = 0x84
	DW_OP_breg21              = 0x85
	DW_OP_breg22              = 0x86
	DW_OP_breg23              = 0x87
	DW_OP_breg24              = 0x88
	DW_OP_breg25              = 0x89
	DW_OP_breg26              = 0x8A
	DW_OP_breg27              = 0x8B
	DW_OP_breg28              = 0x8C
	DW_OP_breg29              = 0x8D
	DW_OP_breg30              = 0x8E
	DW_OP_breg31              = 0x8F
	DW_OP_regx                = 0x90
	DW_OP_fbreg               = 0x91
	DW_OP_bregx               = 0x92
	DW_OP_piece               = 0x93
	DW_OP_deref_size          = 0x94
	DW_OP_xderef_size         = 0x95
	DW_OP_nop                 = 0x96
	DW_OP_push_object_address = 0x97
	DW_OP_call2               = 0x98
	DW_OP_call4               = 0x99
	DW_OP_call_ref            = 0x9a
	DW_OP_form_tls_address    = 0x9b
	DW_OP_call_frame_cfa      = 0x9c
	DW_OP_bit_piece           = 0x9d
	DW_OP_implicit_value      = 0x9e
	DW_OP_stack_value         = 0x9f
	DW_OP_lo_user             = 0xe0
	DW_OP_hi_user             = 0xff
)

// ============================================================================
// DW_LNS standard opcode
// ============================================================================
const (
	DW_LNS_copy               = 0x01
	DW_LNS_advance_pc         = 0x02
	DW_LNS_advance_line       = 0x03
	DW_LNS_set_file           = 0x04
	DW_LNS_set_column         = 0x05
	DW_LNS_negate_stmt        = 0x06
	DW_LNS_set_basic_block    = 0x07
	DW_LNS_const_add_pc       = 0x08
	DW_LNS_fixed_advance_pc   = 0x09
	DW_LNS_set_prologue_end   = 0x0A
	DW_LNS_set_epilogue_begin = 0x0B
	DW_LNS_set_isa            = 0x0C
)

// DW_LNS name map
var dwLnsNameMap = map[uint8]string{
	DW_LNS_copy:               "DW_LNS_copy",
	DW_LNS_advance_pc:         "DW_LNS_advance_pc",
	DW_LNS_advance_line:       "DW_LNS_advance_line",
	DW_LNS_set_file:           "DW_LNS_set_file",
	DW_LNS_set_column:         "DW_LNS_set_column",
	DW_LNS_negate_stmt:        "DW_LNS_negate_stmt",
	DW_LNS_set_basic_block:    "DW_LNS_set_basic_block",
	DW_LNS_const_add_pc:       "DW_LNS_const_add_pc",
	DW_LNS_fixed_advance_pc:   "DW_LNS_fixed_advance_pc",
	DW_LNS_set_prologue_end:   "DW_LNS_set_prologue_end",
	DW_LNS_set_epilogue_begin: "DW_LNS_set_epilogue_begin",
	DW_LNS_set_isa:            "DW_LNS_set_isa",
}

// ============================================================================
// Extended opcode
// ============================================================================
const (
	DW_LNE_end_sequence      = 0x01
	DW_LNE_set_address       = 0x02
	DW_LNE_define_file       = 0x03
	DW_LNE_set_discriminator = 0x04
	DW_LNE_lo_user           = 0x80
	DW_LNE_hi_user           = 0xFF
)

// DW_OP name
var OpNameMap = map[byte]string{
	DW_OP_addr:                "DW_OP_addr",
	DW_OP_deref:               "DW_OP_deref",
	DW_OP_const1u:             "DW_OP_const1u",
	DW_OP_const1s:             "DW_OP_const1s",
	DW_OP_const2u:             "DW_OP_const2u",
	DW_OP_const2s:             "DW_OP_const2s",
	DW_OP_const4u:             "DW_OP_const4u",
	DW_OP_const4s:             "DW_OP_const4s",
	DW_OP_const8u:             "DW_OP_const8u",
	DW_OP_const8s:             "DW_OP_const8s",
	DW_OP_constu:              "DW_OP_constu",
	DW_OP_consts:              "DW_OP_consts",
	DW_OP_dup:                 "DW_OP_dup",
	DW_OP_drop:                "DW_OP_drop",
	DW_OP_over:                "DW_OP_over",
	DW_OP_pick:                "DW_OP_pick",
	DW_OP_swap:                "DW_OP_swap",
	DW_OP_rot:                 "DW_OP_rot",
	DW_OP_xderef:              "DW_OP_xderef",
	DW_OP_abs:                 "DW_OP_abs",
	DW_OP_and:                 "DW_OP_and",
	DW_OP_div:                 "DW_OP_div",
	DW_OP_minus:               "DW_OP_minus",
	DW_OP_mod:                 "DW_OP_mod",
	DW_OP_mul:                 "DW_OP_mul",
	DW_OP_neg:                 "DW_OP_neg",
	DW_OP_not:                 "DW_OP_not",
	DW_OP_or:                  "DW_OP_or",
	DW_OP_plus:                "DW_OP_plus",
	DW_OP_plus_uconst:         "DW_OP_plus_uconst",
	DW_OP_shl:                 "DW_OP_shl",
	DW_OP_shr:                 "DW_OP_shr",
	DW_OP_shra:                "DW_OP_shra",
	DW_OP_xor:                 "DW_OP_xor",
	DW_OP_skip:                "DW_OP_skip",
	DW_OP_bra:                 "DW_OP_bra",
	DW_OP_eq:                  "DW_OP_eq",
	DW_OP_ge:                  "DW_OP_ge",
	DW_OP_gt:                  "DW_OP_gt",
	DW_OP_le:                  "DW_OP_le",
	DW_OP_lt:                  "DW_OP_lt",
	DW_OP_ne:                  "DW_OP_ne",
	DW_OP_lit0:                "DW_OP_lit0 ",
	DW_OP_lit1:                "DW_OP_lit1 ",
	DW_OP_lit2:                "DW_OP_lit2 ",
	DW_OP_lit3:                "DW_OP_lit3 ",
	DW_OP_lit4:                "DW_OP_lit4 ",
	DW_OP_lit5:                "DW_OP_lit5 ",
	DW_OP_lit6:                "DW_OP_lit6 ",
	DW_OP_lit7:                "DW_OP_lit7 ",
	DW_OP_lit8:                "DW_OP_lit8 ",
	DW_OP_lit9:                "DW_OP_lit9 ",
	DW_OP_lit10:               "DW_OP_lit10",
	DW_OP_lit11:               "DW_OP_lit11",
	DW_OP_lit12:               "DW_OP_lit12",
	DW_OP_lit13:               "DW_OP_lit13",
	DW_OP_lit14:               "DW_OP_lit14",
	DW_OP_lit15:               "DW_OP_lit15",
	DW_OP_lit16:               "DW_OP_lit16",
	DW_OP_lit17:               "DW_OP_lit17",
	DW_OP_lit18:               "DW_OP_lit18",
	DW_OP_lit19:               "DW_OP_lit19",
	DW_OP_lit20:               "DW_OP_lit20",
	DW_OP_lit21:               "DW_OP_lit21",
	DW_OP_lit22:               "DW_OP_lit22",
	DW_OP_lit23:               "DW_OP_lit23",
	DW_OP_lit24:               "DW_OP_lit24",
	DW_OP_lit25:               "DW_OP_lit25",
	DW_OP_lit26:               "DW_OP_lit26",
	DW_OP_lit27:               "DW_OP_lit27",
	DW_OP_lit28:               "DW_OP_lit28",
	DW_OP_lit29:               "DW_OP_lit29",
	DW_OP_lit30:               "DW_OP_lit30",
	DW_OP_lit31:               "DW_OP_lit31",
	DW_OP_reg0:                "DW_OP_reg0",
	DW_OP_reg1:                "DW_OP_reg1",
	DW_OP_reg2:                "DW_OP_reg2",
	DW_OP_reg3:                "DW_OP_reg3",
	DW_OP_reg4:                "DW_OP_reg4",
	DW_OP_reg5:                "DW_OP_reg5",
	DW_OP_reg6:                "DW_OP_reg6",
	DW_OP_reg7:                "DW_OP_reg7",
	DW_OP_reg8:                "DW_OP_reg8",
	DW_OP_reg9:                "DW_OP_reg9",
	DW_OP_reg10:               "DW_OP_reg10",
	DW_OP_reg11:               "DW_OP_reg11",
	DW_OP_reg12:               "DW_OP_reg12",
	DW_OP_reg13:               "DW_OP_reg13",
	DW_OP_reg14:               "DW_OP_reg14",
	DW_OP_reg15:               "DW_OP_reg15",
	DW_OP_reg16:               "DW_OP_reg16",
	DW_OP_reg17:               "DW_OP_reg17",
	DW_OP_reg18:               "DW_OP_reg18",
	DW_OP_reg19:               "DW_OP_reg19",
	DW_OP_reg20:               "DW_OP_reg20",
	DW_OP_reg21:               "DW_OP_reg21",
	DW_OP_reg22:               "DW_OP_reg22",
	DW_OP_reg23:               "DW_OP_reg23",
	DW_OP_reg24:               "DW_OP_reg24",
	DW_OP_reg25:               "DW_OP_reg25",
	DW_OP_reg26:               "DW_OP_reg26",
	DW_OP_reg27:               "DW_OP_reg27",
	DW_OP_reg28:               "DW_OP_reg28",
	DW_OP_reg29:               "DW_OP_reg29",
	DW_OP_reg30:               "DW_OP_reg30",
	DW_OP_reg31:               "DW_OP_reg31",
	DW_OP_breg0:               "DW_OP_breg0",
	DW_OP_breg1:               "DW_OP_breg1",
	DW_OP_breg2:               "DW_OP_breg2",
	DW_OP_breg3:               "DW_OP_breg3",
	DW_OP_breg4:               "DW_OP_breg4",
	DW_OP_breg5:               "DW_OP_breg5",
	DW_OP_breg6:               "DW_OP_breg6",
	DW_OP_breg7:               "DW_OP_breg7",
	DW_OP_breg8:               "DW_OP_breg8",
	DW_OP_breg9:               "DW_OP_breg9",
	DW_OP_breg10:              "DW_OP_breg10",
	DW_OP_breg11:              "DW_OP_breg11",
	DW_OP_breg12:              "DW_OP_breg12",
	DW_OP_breg13:              "DW_OP_breg13",
	DW_OP_breg14:              "DW_OP_breg14",
	DW_OP_breg15:              "DW_OP_breg15",
	DW_OP_breg16:              "DW_OP_breg16",
	DW_OP_breg17:              "DW_OP_breg17",
	DW_OP_breg18:              "DW_OP_breg18",
	DW_OP_breg19:              "DW_OP_breg19",
	DW_OP_breg20:              "DW_OP_breg20",
	DW_OP_breg21:              "DW_OP_breg21",
	DW_OP_breg22:              "DW_OP_breg22",
	DW_OP_breg23:              "DW_OP_breg23",
	DW_OP_breg24:              "DW_OP_breg24",
	DW_OP_breg25:              "DW_OP_breg25",
	DW_OP_breg26:              "DW_OP_breg26",
	DW_OP_breg27:              "DW_OP_breg27",
	DW_OP_breg28:              "DW_OP_breg28",
	DW_OP_breg29:              "DW_OP_breg29",
	DW_OP_breg30:              "DW_OP_breg30",
	DW_OP_breg31:              "DW_OP_breg31",
	DW_OP_regx:                "DW_OP_regx",
	DW_OP_fbreg:               "DW_OP_fbreg",
	DW_OP_bregx:               "DW_OP_bregx",
	DW_OP_piece:               "DW_OP_piece",
	DW_OP_deref_size:          "DW_OP_deref_size",
	DW_OP_xderef_size:         "DW_OP_xderef_size",
	DW_OP_nop:                 "DW_OP_nop",
	DW_OP_push_object_address: "DW_OP_push_object_address",
	DW_OP_call2:               "DW_OP_call2",
	DW_OP_call4:               "DW_OP_call4",
	DW_OP_call_ref:            "DW_OP_call_ref",
	DW_OP_form_tls_address:    "DW_OP_form_tls_address",
	DW_OP_call_frame_cfa:      "DW_OP_call_frame_cfa",
	DW_OP_bit_piece:           "DW_OP_bit_piece",
	DW_OP_implicit_value:      "DW_OP_implicit_value",
	DW_OP_stack_value:         "DW_OP_stack_value",
	DW_OP_lo_user:             "DW_OP_lo_user",
	DW_OP_hi_user:             "DW_OP_hi_user",
}

// DW_OP oprand length
var OpSizeMap = map[byte]int{
	DW_OP_addr:                1,
	DW_OP_deref:               0,
	DW_OP_const1u:             1,
	DW_OP_const1s:             1,
	DW_OP_const2u:             1,
	DW_OP_const2s:             1,
	DW_OP_const4u:             1,
	DW_OP_const4s:             1,
	DW_OP_const8u:             1,
	DW_OP_const8s:             1,
	DW_OP_constu:              1,
	DW_OP_consts:              1,
	DW_OP_dup:                 0,
	DW_OP_drop:                0,
	DW_OP_over:                0,
	DW_OP_pick:                1,
	DW_OP_swap:                0,
	DW_OP_rot:                 0,
	DW_OP_xderef:              0,
	DW_OP_abs:                 0,
	DW_OP_and:                 0,
	DW_OP_div:                 0,
	DW_OP_minus:               0,
	DW_OP_mod:                 0,
	DW_OP_mul:                 0,
	DW_OP_neg:                 0,
	DW_OP_not:                 0,
	DW_OP_or:                  0,
	DW_OP_plus:                0,
	DW_OP_plus_uconst:         1,
	DW_OP_shl:                 0,
	DW_OP_shr:                 0,
	DW_OP_shra:                0,
	DW_OP_xor:                 0,
	DW_OP_skip:                1,
	DW_OP_bra:                 1,
	DW_OP_eq:                  0,
	DW_OP_ge:                  0,
	DW_OP_gt:                  0,
	DW_OP_le:                  0,
	DW_OP_lt:                  0,
	DW_OP_ne:                  0,
	DW_OP_lit0:                0,
	DW_OP_lit1:                0,
	DW_OP_lit2:                0,
	DW_OP_lit31:               0,
	DW_OP_reg0:                0,
	DW_OP_reg1:                0,
	DW_OP_reg31:               0,
	DW_OP_breg0:               1,
	DW_OP_breg1:               1,
	DW_OP_breg31:              1,
	DW_OP_regx:                1,
	DW_OP_fbreg:               1,
	DW_OP_bregx:               2,
	DW_OP_piece:               1,
	DW_OP_deref_size:          1,
	DW_OP_xderef_size:         1,
	DW_OP_nop:                 0,
	DW_OP_push_object_address: 0,
	DW_OP_call2:               1,
	DW_OP_call4:               1,
	DW_OP_call_ref:            1,
	DW_OP_form_tls_address:    0,
	DW_OP_call_frame_cfa:      0,
	DW_OP_bit_piece:           2,
	DW_OP_implicit_value:      2,
	DW_OP_stack_value:         0,
	DW_OP_lo_user:             0,
	DW_OP_hi_user:             0,
}

// DWARF Exception Header Encoding(lower 4bits for format of the data)
const DW_EH_PE_omit = 0xFF // No value is present.
const (
	DW_EH_PE_uleb128 = 0x01 // unsigned LEB128
	DW_EH_PE_data2   = 0x02 // A 2 bytes unsigned value.
	DW_EH_PE_data4   = 0x03 // A 4 bytes unsigned value.
	DW_EH_PE_data8   = 0x04 // An 8 bytes unsigned value.
	DW_EH_PE_sleb128 = 0x09 // signed LEB128
	DW_EH_PE_sdata2  = 0x0A // A 2 bytes signed value.
	DW_EH_PE_sdata4  = 0x0B // A 4 bytes signed value.
	DW_EH_PE_sdata8  = 0x0C // An 8 bytes signed value.
)

// DWARF Exception Header Encoding(upper 4bits for application)
const (
	DW_EH_PE_absptr   = 0x00 // Value is used with no modification.
	DW_EH_PE_pcrel    = 0x10 // Value is reletive to the current program counter.
	DW_EH_PE_datarel  = 0x30 // Value is reletive to the beginning of the .eh_frame_hdr section.
	DW_EH_PE_funcrel  = 0x40 // Value is relative to start of function.
	DW_EH_PE_aligned  = 0x50 // Value is aligned: padding bytes are inserted as required to make value be naturally aligned.
	DW_EH_PE_indirect = 0x80 // This is actually the address of the real value.
)

// CFA instruction High 2Bits
const (
	DW_CFA_advance_loc = 0x01
	DW_CFA_offset      = 0x02
	DW_CFA_restore     = 0x03
)

// CFA instruction Low 6Bits
const (
	DW_CFA_nop                          = 0x00
	DW_CFA_set_loc                      = 0x01
	DW_CFA_advance_loc1                 = 0x02
	DW_CFA_advance_loc2                 = 0x03
	DW_CFA_advance_loc4                 = 0x04
	DW_CFA_offset_extended              = 0x05
	DW_CFA_restore_extended             = 0x06
	DW_CFA_undefined                    = 0x07
	DW_CFA_same_value                   = 0x08
	DW_CFA_register                     = 0x09
	DW_CFA_remember_state               = 0x0A
	DW_CFA_restore_state                = 0x0B
	DW_CFA_def_cfa                      = 0x0C
	DW_CFA_def_cfa_register             = 0x0D
	DW_CFA_def_cfa_offset               = 0x0E
	DW_CFA_def_cfa_expression           = 0x0F
	DW_CFA_expression                   = 0x10
	DW_CFA_offset_extended_sf           = 0x11
	DW_CFA_def_cfa_sf                   = 0x12
	DW_CFA_def_cfa_offset_sf            = 0x13
	DW_CFA_val_offset                   = 0x14
	DW_CFA_val_offset_sf                = 0x15
	DW_CFA_val_expression               = 0x16
	DW_CFA_lo_user                      = 0x1c
	DW_CFA_hi_user                      = 0x3F
	DW_CFA_GNU_args_size                = 0x2E
	DW_CFA_GNU_negative_offset_extended = 0x2F
)

var CFANameMap = map[byte]string{
	DW_CFA_nop:                          "DW_CFA_nop",
	DW_CFA_set_loc:                      "DW_CFA_set_loc",
	DW_CFA_advance_loc1:                 "DW_CFA_advance_loc1",
	DW_CFA_advance_loc2:                 "DW_CFA_advance_loc2",
	DW_CFA_advance_loc4:                 "DW_CFA_advance_loc4",
	DW_CFA_offset_extended:              "DW_CFA_offset_extended",
	DW_CFA_restore_extended:             "DW_CFA_restore_extended",
	DW_CFA_undefined:                    "DW_CFA_undefined",
	DW_CFA_same_value:                   "DW_CFA_same_value",
	DW_CFA_register:                     "DW_CFA_register",
	DW_CFA_remember_state:               "DW_CFA_remember_state",
	DW_CFA_restore_state:                "DW_CFA_restore_state",
	DW_CFA_def_cfa:                      "DW_CFA_def_cfa",
	DW_CFA_def_cfa_register:             "DW_CFA_def_cfa_register",
	DW_CFA_def_cfa_offset:               "DW_CFA_def_cfa_offset",
	DW_CFA_def_cfa_expression:           "DW_CFA_def_cfa_expression",
	DW_CFA_expression:                   "DW_CFA_expression",
	DW_CFA_offset_extended_sf:           "DW_CFA_offset_extended_sf",
	DW_CFA_def_cfa_sf:                   "DW_CFA_def_cfa_sf",
	DW_CFA_def_cfa_offset_sf:            "DW_CFA_def_cfa_offset_sf",
	DW_CFA_GNU_args_size:                "DW_CFA_GNU_args_size",
	DW_CFA_GNU_negative_offset_extended: "DW_CFA_GNU_negative_offset_extended",
}

// Language name        Value       Default Lower Bound
const (
	DW_LANG_C89            = 0x0001 // 0
	DW_LANG_C              = 0x0002 // 0
	DW_LANG_Ada83          = 0x0003 // 1
	DW_LANG_C_plus_plus    = 0x0004 // 0
	DW_LANG_Cobol74        = 0x0005 // 1
	DW_LANG_Cobol85        = 0x0006 // 1
	DW_LANG_Fortran77      = 0x0007 // 1
	DW_LANG_Fortran90      = 0x0008 // 1
	DW_LANG_Pascal83       = 0x0009 // 1
	DW_LANG_Modula2        = 0x000a // 1
	DW_LANG_Java           = 0x000b // 0
	DW_LANG_C99            = 0x000c // 0
	DW_LANG_Ada95          = 0x000d // 1
	DW_LANG_Fortran95      = 0x000e // 1
	DW_LANG_PLI            = 0x000f // 1
	DW_LANG_ObjC           = 0x0010 // 0
	DW_LANG_ObjC_plus_plus = 0x0011 // 0
	DW_LANG_UPC            = 0x0012 // 0
	DW_LANG_D              = 0x0013 // 0
	DW_LANG_Python         = 0x0014 // 0
	DW_LANG_OpenCL         = 0x0015 // 0
	DW_LANG_Go             = 0x0016 // 0
	DW_LANG_Modula3        = 0x0017 // 1
	DW_LANG_Haskell        = 0x0018 // 0
	DW_LANG_C_plus_plus_03 = 0x0019 // 0
	DW_LANG_C_plus_plus_11 = 0x001a // 0
	DW_LANG_OCaml          = 0x001b // 0
	DW_LANG_Rust           = 0x001c // 0
	DW_LANG_C11            = 0x001d // 0
	DW_LANG_Swift          = 0x001e // 0
	DW_LANG_Julia          = 0x001f // 1
	DW_LANG_Dylan          = 0x0020 // 0
	DW_LANG_C_plus_plus_14 = 0x0021 // 0
	DW_LANG_Fortran03      = 0x0022 // 1
	DW_LANG_Fortran08      = 0x0023 // 1
	DW_LANG_RenderScript   = 0x0024 // 0
	DW_LANG_BLISS          = 0x0025 // 0
	DW_LANG_lo_user        = 0x8000
	DW_LANG_hi_user        = 0xFFFF
)

var langNameMap = map[uint16]string{
	DW_LANG_C89:            "C89",
	DW_LANG_C:              "C",
	DW_LANG_Ada83:          "Ada83",
	DW_LANG_C_plus_plus:    "C++",
	DW_LANG_Cobol74:        "Cobol74",
	DW_LANG_Cobol85:        "Cobol85",
	DW_LANG_Fortran77:      "Fortran77",
	DW_LANG_Fortran90:      "Fortran90",
	DW_LANG_Pascal83:       "Pascal83",
	DW_LANG_Modula2:        "Modula2",
	DW_LANG_Java:           "Java",
	DW_LANG_C99:            "C99",
	DW_LANG_Ada95:          "Ada95",
	DW_LANG_Fortran95:      "Fortran95",
	DW_LANG_PLI:            "PLI",
	DW_LANG_ObjC:           "Objective-C",
	DW_LANG_ObjC_plus_plus: "Objective-C++",
	DW_LANG_UPC:            "UPC",
	DW_LANG_D:              "D",
	DW_LANG_Python:         "Python",
	DW_LANG_OpenCL:         "OpenCL",
	DW_LANG_Go:             "Go",
	DW_LANG_Modula3:        "Modula3",
	DW_LANG_Haskell:        "Haskell",
	DW_LANG_C_plus_plus_03: "C++03",
	DW_LANG_C_plus_plus_11: "C++11",
	DW_LANG_OCaml:          "OCaml",
	DW_LANG_Rust:           "Rust",
	DW_LANG_C11:            "C11",
	DW_LANG_Swift:          "Swift",
	DW_LANG_Julia:          "Julia",
	DW_LANG_Dylan:          "Dylan",
	DW_LANG_C_plus_plus_14: "C_plus_plus_14",
	DW_LANG_Fortran03:      "Fortran03",
	DW_LANG_Fortran08:      "Fortran08",
	DW_LANG_RenderScript:   "RenderScript",
	DW_LANG_BLISS:          "BLISS",
}

// DWARF5 P237 Table 7.27
// Line number header entry format encodings
const (
	DW_LNCT_path            = 0x1
	DW_LNCT_directory_index = 0x2
	DW_LNCT_timestamp       = 0x3
	DW_LNCT_size            = 0x4
	DW_LNCT_MD5             = 0x5
	DW_LNCT_lo_user         = 0x2000
	DW_LNCT_hi_user         = 0x3f
)

// Compilation Unit Header
// see 7.5.1.1 Compilation Unit Header
// this struct include DWARF Format(32/64), so not same as header size
type Dwarf32CuHdr struct {
	UnitLength        uint64
	DwarfFormat       uint8
	Version           uint16
	UnitType          uint8 // DWARF5 or later
	DebugAbbrevOffset uint32
	AddressSize       uint8
	UnitID            uint64
	TypeSignature     uint64
	TypeOffset        uint64
}

// Line Number Program Header
// see 6.2.4 The Line Number Program Header

type FileNameInfo struct {
	Name         string
	DirIdx       uint64
	LastModified uint64
	Size         uint64
}

type Dwarf32SegmentInfo struct {
	Address uint64
	Length  uint64
}

// this struct include DWARF Format(32/64), so not same as header size
type Dwarf32ArangeInfoHdr struct {
	UnitLength      uint64
	DwarfFormat     uint8
	Version         uint16
	DebugInfoOffset uint32
	AddressSize     uint8
	SegmentSize     uint8
}
type Dwarf32ArangeInfo struct {
	Header   Dwarf32ArangeInfoHdr
	Segments []Dwarf32SegmentInfo
}

type EntryFormat struct {
	TypeCode uint64
	FormCode uint64
}

// this struct include DWARF Format(32/64), so not same as header size
type Dwarf32LineInfoHdr struct {
	UnitLength                uint64
	DwarfFormat               uint8
	Version                   uint16
	HeaderLength              uint32
	AddressSize               uint8 // only verion5 or later
	SegmentSelectorSize       uint8 // only verion5 or later
	MinInstLength             uint8
	MaxInstLength             uint8 // only version4 or later
	DefaultIsStmt             uint8
	LineBase                  int8
	LineRange                 uint8
	OpcodeBase                uint8
	StdOpcodeLengths          []uint8
	DirectoryEntryFormatCount uint8         // only verion5 or later
	DirectoryEntryFormats     []EntryFormat // only verion5 or later
	DirectoriesCount          uint64        // only verion5 or later
	Directories               []string      // only verion5 or later
	FileNameEntryFormatCount  uint8         // only verion5 or later
	FileNameEntryFormats      []EntryFormat // only verion5 or later
	FileNamesCount            uint64        // only verion5 or later
	IncludeDirs               []string      // only verion5 or later
	Files                     []FileNameInfo
}

// Common Information Entry
type Dwarf32CIE struct {
	CIE_id                uint32
	Version               uint8
	Augmentation          string // 1: DWARF2 3: DWARF3 4: DWARF4
	AddressSize           uint8  // Only exists DWARF4
	SegmentSize           uint8  // Only exists DWARF4
	CodeAlignmentFactor   uint32
	DataAlignmentFactor   uint32
	ReturnAddressRegister uint8
	Program               []uint8
}

type Dwarf32FDE struct {
	Length          uint32
	CIEPointer      uint32
	CIEIdx          uint32
	InitialLocation uint32
	AddressRange    uint32
	Program         []uint8
}

type Dwarf32FrameInfo struct {
	CIEs []Dwarf32CIE
	FDEs map[uint64]Dwarf32FDE // address-FDE map
}

type Dwarf32Location struct {
	Reg    uint32
	Offset int32
}

type Dwarf32Var struct {
	Name     string
	FileName string
	Line     uint32
	Colmun   uint32
	Type     uint64
	Location Dwarf32Location
}

const (
	FRAME_TYPE_CFI = 0
)

type Dwarf32FrameBase struct {
	Type int
}

type Dwarf32FuncInfo struct {
	SrcFilePath string
	Name        string
	LinkageName string
	Addr        uint64
	Size        uint32
	FrameBase   uint32
	Args        []Dwarf32Var
	LocalVars   []Dwarf32Var
}

type Dwarf32CuDebugInfo struct {
	FileName   string
	Producer   string
	Language   string
	CompileDir string
	Funcs      map[uint64]Dwarf32FuncInfo
}

func (d *Dwarf32CuDebugInfo) IsRust() bool {
	return d.Language == langNameMap[DW_LANG_Rust]
}

func (d *Dwarf32CuDebugInfo) FilePath() string {
	srcFilePath, _ := filepath.Abs(fmt.Sprintf("%s/%s", d.CompileDir, d.FileName))
	return srcFilePath
}

func ReadAranges(bin []byte) map[uint32]Dwarf32ArangeInfo {
	dbgArangesLen := uint64(len(bin))
	var offset uint64 = 0
	var headerTop uint64 = 0

	var arangeInfos = map[uint32]Dwarf32ArangeInfo{}
	for offset < dbgArangesLen {
		headerTop = offset
		var nextHdrTop uint64 = 0
		var hdrSize uint64 = 0
		arangeInfo := Dwarf32ArangeInfo{}
		arangeInfoHdr := Dwarf32ArangeInfoHdr{}

		// TODO 4 or 8
		// unit_length initial length(4 or 8 bytes)
		tmp, _ := binutil.FromLeToUInt32(bin[offset:])
		offset += 4
		hdrSize += 4
		if tmp < 0xFFFFFF00 {
			// 32-bit DWARF Format
			arangeInfoHdr.UnitLength = uint64(tmp)
			arangeInfoHdr.DwarfFormat = DWARF_32BIT_FORMAT
		} else {
			// 64-bit DWARF Format
			arangeInfoHdr.UnitLength, _ = binutil.FromLeToUInt64(bin[offset:])
			arangeInfoHdr.DwarfFormat = DWARF_64BIT_FORMAT
			offset += 8
			hdrSize += 8
		}
		nextHdrTop = headerTop + hdrSize + arangeInfoHdr.UnitLength

		// version uhalf
		arangeInfoHdr.Version, _ = binutil.FromLeToUInt16(bin[offset:])
		offset += 2

		// header_length 32bit-DWARF/64bit-DWARF
		arangeInfoHdr.DebugInfoOffset, _ = binutil.FromLeToUInt32(bin[offset:])
		offset += 4

		// address_size ubyte
		// The size of an address in bytes on the target architecture.
		arangeInfoHdr.AddressSize = bin[offset]
		offset += 1

		// segment_size ubyte
		// The size of a segment selector in bytes on the target architecture.
		// If the target system uses a flat address space, this value is 0.
		arangeInfoHdr.SegmentSize = bin[offset]
		offset += 1

		// header size must be devided by (AddressSize x 2)
		alighnmentSize := uint64(arangeInfoHdr.AddressSize)
		paddingSize := alighnmentSize - (offset-headerTop)%alighnmentSize
		offset += paddingSize

		arangeInfo.Header = arangeInfoHdr
		arangeInfo.Segments = []Dwarf32SegmentInfo{}

		// TODO
		// spec version 2 is pair of address, length
		for {
			seg := Dwarf32SegmentInfo{}
			if arangeInfoHdr.AddressSize == 8 {
				address, _ := binutil.FromLeToUInt64(bin[offset:])
				offset += 8
				length, _ := binutil.FromLeToUInt64(bin[offset:])
				offset += 8
				logger.TLog("address:0x%x, length: 0x%x\n", address, length)
				if address == 0 && length == 0 {
					break
				}
				seg.Address = address
				seg.Length = length
			} else {
				// TODO 32bit address
				address, _ := binutil.FromLeToUInt32(bin[offset:])
				offset += 4
				length, _ := binutil.FromLeToUInt32(bin[offset:])
				offset += 4

				logger.TLog("address:0x%x, length: 0x%x\n", address, length)
				if address == 0 && length == 0 {
					break
				}
				seg.Address = uint64(address)
				seg.Length = uint64(length)
			}
			arangeInfo.Segments = append(arangeInfo.Segments, seg)
		}
		if nextHdrTop != offset {
			offset += nextHdrTop - offset
		}
		arangeInfos[arangeInfo.Header.DebugInfoOffset] = arangeInfo
	}
	return arangeInfos
}

type EncodedValue struct {
	signed bool
	uVal   uint64
	sVal   int64
}

func readExceptionHeaderEncodedField(enc uint8, bin []byte) (EncodedValue, int) {
	var offset uint64 = 0
	var encVal EncodedValue
	encVal.signed = false

	switch enc & 0x0F {
	case DW_EH_PE_uleb128:
		tmp, size := ReaduLEB128(bin[offset:])
		encVal.uVal = tmp
		offset += uint64(size)
	case DW_EH_PE_data2:
		tmp, _ := binutil.FromLeToUInt16(bin[offset:])
		encVal.uVal = uint64(tmp)
		offset += 2
	case DW_EH_PE_data4:
		tmp, _ := binutil.FromLeToUInt32(bin[offset:])
		encVal.uVal = uint64(tmp)
		offset += 4
	case DW_EH_PE_data8:
		tmp, _ := binutil.FromLeToUInt64(bin[offset:])
		encVal.uVal = uint64(tmp)
	case DW_EH_PE_sleb128:
		tmp, size := ReadsLEB128(bin[offset:])
		encVal.signed = true
		encVal.sVal = tmp
		offset += uint64(size)
		offset += 8
	case DW_EH_PE_sdata2:
		tmp, _ := binutil.FromLeToInt16(bin[offset:])
		encVal.signed = true
		encVal.sVal = int64(tmp)
		offset += 2
	case DW_EH_PE_sdata4:
		tmp, _ := binutil.FromLeToInt32(bin[offset:])
		encVal.signed = true
		encVal.sVal = int64(tmp)
		offset += 4
	case DW_EH_PE_sdata8:
		tmp, _ := binutil.FromLeToInt64(bin[offset:])
		encVal.signed = true
		encVal.sVal = int64(tmp)
		offset += 8
	default:
		panic("Unexpected Encoding")
	}
	return encVal, int(offset)
}

func ReadFrameHdr(bin []byte) {
	// .eh_frame_hdr

	var offset uint64 = 0
	// version ubyte
	version := uint8(bin[offset])
	offset += 1
	logger.DLog("version:%d\n", version)

	// eh_frame_ptr_enc ubyte
	ehFramePtrEnc := uint8(bin[offset])
	offset += 1
	logger.DLog("eh_frame_ptr_enc:0x%0X\n", ehFramePtrEnc)

	// fde_count_enc ubyte
	fdeCountEnc := uint8(bin[offset])
	offset += 1
	logger.DLog("fde_count_enc:0x%0X\n", fdeCountEnc)

	// table_enc ubyte
	tableEnc := uint8(bin[offset])
	offset += 1
	logger.DLog("table_enc:0x%0X\n", tableEnc)

	// eh_frame_ptr
	ehFramePtr, size := readExceptionHeaderEncodedField(ehFramePtrEnc, bin[offset:])
	offset += uint64(size)
	logger.DLog("uVal:%d, sVal%d", ehFramePtr.uVal, ehFramePtr.sVal)

	// fde_count
	fdeCount, size := readExceptionHeaderEncodedField(fdeCountEnc, bin[offset:])
	offset += uint64(size)

	var tblCnt uint64 = fdeCount.uVal
	logger.DLog("uVal:%d", fdeCount.uVal)
	if fdeCount.signed {
		tblCnt = uint64(fdeCount.sVal)
	}
	offset += readBinarySearchTable(tableEnc, bin[offset:], tblCnt)
}

func readBinarySearchTable(tableEnc uint8, bin []byte, fdeCount uint64) uint64 {
	var offset uint64 = 0
	// binary search table
	for i := 0; i < int(fdeCount); i++ {
		// initial location(Program Counter)
		_, size := readExceptionHeaderEncodedField(tableEnc, bin[offset:])
		//fmt.Printf("initial location: 0x%x\n", uint32(initialLocationField.sVal))
		offset += uint64(size)

		// address(offset of FDE)
		_, size = readExceptionHeaderEncodedField(tableEnc, bin[offset:])
		//fmt.Printf("address: 0x%x\n", addressField.sVal)
		offset += uint64(size)
	}

	return offset
}

// See DWARF2 7.23 Call Frame Information
func readCFAInstruction(bin []uint8, dwarfFormat uint64) uint64 {
	var offset uint64 = 0
	cfaOpcode := bin[0]
	offset++
	hi2bits := (cfaOpcode & 0xC0) >> 6
	low6bits := cfaOpcode & 0x3F
	if hi2bits == DW_CFA_advance_loc {
		logger.DLog("cfa ins DW_CFA_advance_loc")
		// TODO
		return offset
	}
	if hi2bits == DW_CFA_offset {
		logger.DLog("cfa ins DW_CFA_offset")
		_, size := ReaduLEB128(bin[offset:])
		offset += uint64(size)
		return offset
	}
	if hi2bits == DW_CFA_restore {
		logger.DLog("cfa ins DW_CFA_restore")
		// TODO
		return offset
	}

	name := CFANameMap[low6bits]
	logger.DLog("cfa ins:%s", name)
	switch low6bits {
	case DW_CFA_nop:
		// no operand
		break
	case DW_CFA_set_loc:
		// no operand
		if dwarfFormat == DWARF_32BIT_FORMAT {
			offset += 4
		} else {
			offset += 8
		}
	case DW_CFA_advance_loc1:
		// TODO
		offset += 1
		break
	case DW_CFA_advance_loc2:
		// TODO
		offset += 2
		break
	case DW_CFA_advance_loc4:
		// TODO
		offset += 4
		break
	case DW_CFA_offset_extended:
		// TODO
		// Operand1 register
		_, size := ReaduLEB128(bin[offset:])
		//fmt.Println(reg)
		offset += uint64(size)

		// Operand2 offset
		_, size = ReaduLEB128(bin[offset:])
		//fmt.Println(op2Offset)
		offset += uint64(size)
		break
	case DW_CFA_restore_extended:
		// Operand1 register
		_, size := ReaduLEB128(bin[offset:])
		offset += uint64(size)
		break
	case DW_CFA_undefined:
		// Operand1 register
		_, size := ReaduLEB128(bin[offset:])
		offset += uint64(size)
		break
	case DW_CFA_same_value:
		// Operand1 register
		_, size := ReaduLEB128(bin[offset:])
		offset += uint64(size)
		break
	case DW_CFA_register:
		// TODO
		// Operand1 register
		_, size := ReaduLEB128(bin[offset:])
		//fmt.Println(reg)
		offset += uint64(size)

		// Operand2 offset
		_, size = ReaduLEB128(bin[offset:])
		//fmt.Println(op2Offset)
		offset += uint64(size)
		break
	case DW_CFA_remember_state:
		break
	case DW_CFA_restore_state:
		break
	case DW_CFA_def_cfa:
		// TODO
		// Operand1 register
		_, size := ReaduLEB128(bin[offset:])
		offset += uint64(size)

		// Operand2 offset
		_, size = ReaduLEB128(bin[offset:])
		offset += uint64(size)
	case DW_CFA_def_cfa_register:
		// Operand2 offset
		cfa_reg, size := ReaduLEB128(bin[offset:])
		fmt.Println(cfa_reg)
		offset += uint64(size)
	case DW_CFA_def_cfa_offset:
		// TODO
		cfaOffset, size := ReaduLEB128(bin[offset:])
		logger.DLog("cfaOffset:0x%X", cfaOffset)
		offset += uint64(size)
	default:
		logger.DLog("unexpected ins:0x%X", cfaOpcode)
		panic("unexpected cfa")
	}

	return offset
}

func ReadFrameInfo(bin []byte) Dwarf32FrameInfo {

	var frameInfo Dwarf32FrameInfo
	frameInfo.FDEs = make(map[uint64]Dwarf32FDE)

	// .debug_frame
	// offset-Index Map
	var ciePointerMap map[uint64]uint32 = make(map[uint64]uint32)
	var cie Dwarf32CIE
	var offset uint64 = 0

	var cieIdx uint32 = 0
	ciePointerMap[offset] = cieIdx

	unitLengthSize := 4
	// unit_length initial length(4 or 8 bytes)
	tmp, _ := binutil.FromLeToUInt32(bin[offset:])
	offset += 4

	// initial length
	var initialLength uint64 = 0
	var dwarfFormat uint64 = 0

	if tmp < 0xffffff00 {
		// 32-bit DWARF Format
		initialLength = uint64(tmp)
		dwarfFormat = DWARF_32BIT_FORMAT
	} else {
		// 64-bit DWARF Format
		initialLength, _ = binutil.FromLeToUInt64(bin[offset:])
		dwarfFormat = DWARF_64BIT_FORMAT
		offset += 8
		unitLengthSize += 8
	}

	logger.DLog("%d", initialLength)

	// CIE id
	var cieId uint64 = 0
	if dwarfFormat == DWARF_32BIT_FORMAT {
		tmp, _ := binutil.FromLeToUInt32(bin[offset:])
		cieId = uint64(tmp)
		offset += 4
	} else {
		cieId, _ = binutil.FromLeToUInt64(bin[offset:])
		offset += 8
	}
	logger.DLog("%d", cieId)
	cie.CIE_id = uint32(cieId)

	// version ubyte
	// DWARF 2: 1, DWARF 3: 3, DWARF 4: 4
	version := uint8(bin[offset])
	cie.Version = version
	offset += 1
	logger.DLog("%d", version)

	// augmentation
	// NULL terminated UTF-8 string
	augmentation := binutil.GetString(bin, offset)
	cie.Augmentation = augmentation
	offset += uint64(len(augmentation) + 1)

	// "eh" If the Augmentation string has the value "eh", then the EH Data field shall be present.
	if augmentation == "eh" {
		var ehData uint64 = 0
		if dwarfFormat == DWARF_32BIT_FORMAT {
			tmp, _ := binutil.FromLeToUInt32(bin[offset:])
			ehData = uint64(tmp)
			offset += 4
		} else {
			tmp, _ := binutil.FromLeToUInt64(bin[offset:])
			ehData = uint64(tmp)
			offset += 8
		}

		logger.DLog("%d", ehData)
	}

	// code_alignment_factor
	codeAlignmentFactor, size := ReaduLEB128(bin[offset:])
	cie.CodeAlignmentFactor = uint32(codeAlignmentFactor)
	logger.DLog("%d", codeAlignmentFactor)
	offset += uint64(size)

	// data_alignment_factor
	dataAlignmentFactor, size := ReadsLEB128(bin[offset:])
	cie.DataAlignmentFactor = uint32(dataAlignmentFactor)
	logger.DLog("%d", dataAlignmentFactor)
	offset += uint64(size)

	// return_address_register
	return_address_register, size := ReaduLEB128(bin[offset:])
	cie.ReturnAddressRegister = uint8(return_address_register)
	logger.DLog("%d", return_address_register)
	offset += uint64(size)

	// Augmentation Length
	// An unsigned LEB128 encoded value indicating the length in bytes of the Augmentation Data.
	// This field is only present if the Augmentation String contains the character 'z'.
	var AugmentationLength uint64 = 0
	if strings.Contains(augmentation, "z") {
		AugmentationLength, size = ReaduLEB128(bin[offset:])
		offset += uint64(size)
		logger.DLog("%d", AugmentationLength)
	}

	// Augmentation Data
	// A block of data whose contents are defined by the contents of the Augmentation String as described below.
	// This field is only present if the Augmentation String contains the character 'z'.
	var ptrEnc uint8 = 0
	if strings.Contains(augmentation, "z") {
		var augDataPos uint64 = 0
		for augDataPos < AugmentationLength {
			if strings.Contains(augmentation, "R") {
				// "zR"
				// A 'R' may be present at any position after the first character of the string.
				// This character may only be present if 'z' is the first character of the string.
				// If present, The Augmentation Data shall include a 1 byte argument that represents the pointer encoding for the address pointers used in the FDE.
				ptrEnc = bin[offset]
				offset += 1
				augDataPos += 1
				logger.DLog("%d", ptrEnc)
			} else {
				panic("Unexpected augmentation")
			}
		}
	}

	// std::uint8_t fde_pointer_encoding = DW_EH_PE_udata8 | DW_EH_PE_absptr;
	// fde_pointer_encoding := 4
	// initial_instructions
	// array of DW_CFA_xxx
	var insPos uint64 = 0
	insLen := uint64(unitLengthSize + int(initialLength) - int(offset))
	progStart := offset
	progEnd := uint64(offset + insLen)
	program := bin[progStart:progEnd]
	cie.Program = program
	for insPos < insLen {
		insSize := readCFAInstruction(bin[offset:], dwarfFormat)
		offset += uint64(insSize)
		insPos += uint64(insSize)
	}
	logger.DLog("%d", offset)
	frameInfo.CIEs = append(frameInfo.CIEs, cie)

	// ====================================================
	// FDE Frame Description Entry Format
	// Note: for DWARF 2
	// ====================================================
	secSize := uint64(len(bin))
	for offset < secSize {
		var fde Dwarf32FDE
		// length
		length, _ := binutil.FromLeToUInt32(bin[offset:])
		fde.Length = length
		offset += 4
		logger.DLog("length: %d", length)

		// CIE Pointer
		ciePointer, _ := binutil.FromLeToUInt32(bin[offset:])
		cieIdx := ciePointerMap[uint64(ciePointer)]
		fde.CIEPointer = ciePointer
		fde.CIEIdx = cieIdx
		offset += 4
		logger.DLog("ciePointer: 0x%X, cieIdx:%d\n", ciePointer, cieIdx)

		// initial_location
		// TODO: addressSize: 4
		initial_location, _ := binutil.FromLeToUInt32(bin[offset:])
		fde.InitialLocation = initial_location
		offset += 4
		logger.DLog("initial_location: 0x%X\n", initial_location)

		// address_range
		// TODO: addressSize: 4
		address_range, _ := binutil.FromLeToUInt32(bin[offset:])
		fde.AddressRange = address_range
		offset += 4
		logger.DLog("address_range: 0x%X\n", address_range)

		var insTotal uint64 = 0
		progStart := offset
		progLength := uint64(length - 12)
		progEnd := offset + progLength
		fde.Program = bin[progStart:progEnd]
		for insTotal < progLength {
			insSize := readCFAInstruction(bin[offset:], dwarfFormat)
			insTotal += insSize
			offset += uint64(insSize)
		}
		logger.DLog("InitialLocation: 0x%X\n", fde.InitialLocation)
		frameInfo.FDEs[uint64(fde.InitialLocation)] = fde
	}
	return frameInfo
}

func ReadDebugInfo(offsetArangeMap map[uint32]Dwarf32ArangeInfo, frameInfo Dwarf32FrameInfo, debug_info []byte, elfObj elf.ElfObject, offsetLineInfoMap map[uint64]Dwarf32LineInfoHdr) []Dwarf32CuDebugInfo {
	var dbgInfolen uint64 = uint64(len(debug_info))
	dbgInfos := []Dwarf32CuDebugInfo{}
	count := 0

	var cuLineInfoOffset uint64 = 0

	cppTmpFunc := make(map[uint64]Dwarf32FuncInfo)

	dbgStrSec := elfObj.GetSectionBinByName(".debug_str")
	var offset uint64 = 0
	for offset < dbgInfolen {
		var cuTop uint64 = offset
		curArrangeInfo := offsetArangeMap[uint32(offset)]
		cuh := NewDwarf32Cuh(debug_info[offset:])
		logger.DLog("******** cu header info ********")
		logger.DLog("size: 0x%x\n", cuh.UnitLength)
		logger.DLog("version: %d\n", cuh.Version)
		logger.DLog("debug_abbrev_offset: %d\n", cuh.DebugAbbrevOffset)
		logger.DLog("address_size: %d\n", cuh.AddressSize)

		cuDbgInfo := Dwarf32CuDebugInfo{}
		cuDbgInfo.Funcs = map[uint64]Dwarf32FuncInfo{}

		// compilation unit header
		debug_abbrev := elfObj.GetSectionBinByName(".debug_abbrev")
		abbrevTbl := ReadAbbrevTbl(debug_abbrev[cuh.DebugAbbrevOffset:])

		abbrevMap := map[uint64]Abbrev{}
		for _, abbrev := range abbrevTbl {
			abbrevMap[abbrev.Id] = abbrev
		}

		var cuEnd uint64 = (cuh.UnitLength + 4)
		if cuh.DwarfFormat == DWARF_64BIT_FORMAT {
			cuEnd = offset + uint64(cuh.UnitLength+8)
		}
		cuEnd += cuTop
		offset += 11
		var hasSibling = false
		var siblingOffset uint64 = 0
		var dwarfFuncInfo *Dwarf32FuncInfo = nil
		var funcArg *Dwarf32Var = nil
		var localVar *Dwarf32Var = nil

		for offset < cuEnd {
			entryOffset := offset
			id, size := ReaduLEB128(debug_info[offset:])
			if id == 0 {
				offset++
				continue
			}

			if hasSibling {
				if siblingOffset == offset {
					logger.DLog("found sibling [%X], clear function Info\n", offset)

					if dwarfFuncInfo != nil {
						if dwarfFuncInfo.Addr != 0 {
							// skip if addr not set(must be library function)
							logger.TLog("name:%s, linkageName:%s addr:0x%X\n", dwarfFuncInfo.Name, dwarfFuncInfo.LinkageName, dwarfFuncInfo.Addr)
							cuDbgInfo.Funcs[dwarfFuncInfo.Addr] = *dwarfFuncInfo
						} else {
							// addr not fixed, maybe c++ function delc, add tmpFuncs
							cppTmpFunc[uint64(entryOffset)] = *dwarfFuncInfo
						}
					}

					hasSibling = false
					siblingOffset = 0
					dwarfFuncInfo = nil
					funcArg = nil
					localVar = nil
				}
			} else {
				logger.DLog("clear function Info\n")
				dwarfFuncInfo = nil
				funcArg = nil
				localVar = nil
			}

			abbrev := abbrevMap[id]
			offset += uint64(size)

			if abbrev.Tag == DW_TAG_subprogram {
				dwarfFuncInfo = &Dwarf32FuncInfo{}
			}

			if abbrev.Tag == DW_TAG_variable {
				localVar = &Dwarf32Var{}
			}
			if abbrev.Tag == DW_TAG_formal_parameter {
				funcArg = &Dwarf32Var{}
			}

			for _, attr := range abbrev.Attrs {
				attrName := AttrNameMap[attr.Attr]
				logger.DLog("[%6x] %s", entryOffset, attrName)
				if attr.Attr == DW_AT_sibling {
					logger.DLog("sibling found !")
					hasSibling = true
				}
				switch attr.Form {
				case DW_FORM_addr:
					// TODO addr
					var funcaddr uint64 = 0
					if cuh.AddressSize == 2 {
						addr, _ := binutil.FromLeToUInt16(debug_info[offset:])
						funcaddr = uint64(addr)
						logger.TLog("Attr: %s value:0x%04x\n", attrName, addr)
					}
					if cuh.AddressSize == 4 {
						addr, _ := binutil.FromLeToUInt32(debug_info[offset:])
						funcaddr = uint64(addr)
						logger.TLog("Attr: %s value:0x%08x\n", attrName, addr)
					}
					if cuh.AddressSize == 8 {
						addr, _ := binutil.FromLeToUInt64(debug_info[offset:])
						funcaddr = addr
						logger.TLog("Attr: %s value:0x%016x\n", attrName, addr)
					}

					// DW_AT_low_pc  is function start address,
					// DW_AT_high_pc is function end address,
					if attr.Attr == DW_AT_low_pc {
						if abbrev.Tag == DW_TAG_subprogram {
							dwarfFuncInfo.Addr = funcaddr
						}
					}
					offset += uint64(cuh.AddressSize)
				case DW_FORM_block2:
					blk2, _ := binutil.FromLeToUInt16(debug_info[offset:])
					offset += 2
					offset += uint64(blk2)
					logger.DLog("Attr: %s value:0x%016x\n", attrName, blk2)
				case DW_FORM_block4:
					blk4, _ := binutil.FromLeToUInt32(debug_info[offset:])
					offset += 4
					offset += uint64(blk4)
					logger.DLog("Attr: %s value:0x%016x\n", attrName, blk4)
				case DW_FORM_strp:
					dbgStrOffset, _ := binutil.FromLeToUInt32(debug_info[offset:])
					offset += uint64(unsafe.Sizeof(uint32(0)))
					str := binutil.GetString(dbgStrSec, uint64(dbgStrOffset))
					logger.DLog("%s: %s\n", attrName, str)
					if abbrev.Tag == DW_TAG_compile_unit {
						if attr.Attr == DW_AT_name {
							// for Rust
							if cuDbgInfo.IsRust() {
								idx := strings.LastIndex(str, "@")
								str = str[:idx-1]
							}
							cuDbgInfo.FileName = str
						} else if attr.Attr == DW_AT_comp_dir {
							cuDbgInfo.CompileDir = str
						} else if attr.Attr == DW_AT_producer {
							cuDbgInfo.Producer = str
						} else {
							panic("---------------")
						}
					}
					if abbrev.Tag == DW_TAG_subprogram {
						if attr.Attr == DW_AT_name {
							dwarfFuncInfo.Name = str
						} else if attr.Attr == DW_AT_linkage_name {
							dwarfFuncInfo.LinkageName = str
						} else if attr.Attr == DW_AT_MIPS_linkage_name {
							// arm-none-eabi-gcc
							dwarfFuncInfo.Name = str
						} else {
							panic("not name!")
						}
					}
				case DW_FORM_data1:
					// TODO check value
					// P207 TOOD DW_FORM_implicit_const
					by := debug_info[offset]
					offset += 1
					logger.TLog("Attr: %s value:0x%02x\n", attrName, by)
					if attr.Attr == DW_AT_decl_file {
						lineInfoHdr := offsetLineInfoMap[cuLineInfoOffset]
						fileName := lineInfoHdr.Files[by-1].Name
						logger.TLog("Attr: %s filename:%s\n", attrName, fileName)
						if abbrev.Tag == DW_TAG_formal_parameter {
							funcArg.FileName = fileName
						}
						if abbrev.Tag == DW_TAG_variable {
							localVar.FileName = fileName
						}
					}
					if attr.Attr == DW_AT_decl_line {
						logger.TLog("decl_line: %d\n", by)
						if abbrev.Tag == DW_TAG_formal_parameter {
							funcArg.Line = uint32(by)
						}
						if abbrev.Tag == DW_TAG_variable {
							localVar.Line = uint32(by)
						}
					}
					if attr.Attr == DW_AT_decl_column {
						logger.TLog("decl_column: %d\n", by)
						if abbrev.Tag == DW_TAG_formal_parameter {
							funcArg.Colmun = uint32(by)
						}
						if abbrev.Tag == DW_TAG_variable {
							localVar.Colmun = uint32(by)
						}
					}
				case DW_FORM_data2:
					// TODO check value
					val, _ := binutil.FromLeToUInt16(debug_info[offset:])
					logger.TLog("Attr: %s value:0x%04x\n", attrName, val)
					if attr.Attr == DW_AT_high_pc {
						dwarfFuncInfo.Size = uint32(val)
					}
					if attr.Attr == DW_AT_decl_line {
						logger.TLog("decl_line: %d\n", val)
						if abbrev.Tag == DW_TAG_formal_parameter {
							funcArg.Line = uint32(val)
						}
						if abbrev.Tag == DW_TAG_variable {
							localVar.Line = uint32(val)
						}
					}
					if attr.Attr == DW_AT_decl_column {
						logger.TLog("decl_column: %d\n", val)
						if abbrev.Tag == DW_TAG_formal_parameter {
							funcArg.Colmun = uint32(val)
						}
						if abbrev.Tag == DW_TAG_variable {
							localVar.Colmun = uint32(val)
						}
					}

					if attr.Attr == DW_AT_language {
						lang := "unknown language"
						lang, exist := langNameMap[val]
						if exist {
							cuDbgInfo.Language = lang
						}
					}
					offset += 2
				case DW_FORM_data4:
					// TODO check value
					val, _ := binutil.FromLeToUInt32(debug_info[offset:])
					logger.TLog("Attr: %s value:0x%08x\n", attrName, val)
					if attr.Attr == DW_AT_high_pc {
						if dwarfFuncInfo != nil {
							dwarfFuncInfo.Size = uint32(val)
						}
					}
					if attr.Attr == DW_AT_decl_line {
						logger.TLog("decl_line: %d\n", val)
						if abbrev.Tag == DW_TAG_formal_parameter {
							funcArg.Line = uint32(val)
						}
						if abbrev.Tag == DW_TAG_variable {
							localVar.Line = uint32(val)
						}
					}
					if attr.Attr == DW_AT_decl_column {
						logger.TLog("decl_column: %d\n", val)
						if abbrev.Tag == DW_TAG_formal_parameter {
							funcArg.Colmun = uint32(val)
						}
						if abbrev.Tag == DW_TAG_variable {
							localVar.Colmun = uint32(val)
						}
					}
					offset += 4
				case DW_FORM_data8:
					// TODO check value
					val, _ := binutil.FromLeToUInt64(debug_info[offset:])
					if attr.Attr == DW_AT_high_pc {
						dwarfFuncInfo.Size = uint32(val)
					}
					logger.TLog("Attr: %s value:0x%016x\n", attrName, val)
					offset += 8
				case DW_FORM_string:
					str := binutil.GetString(debug_info[offset:], 0)
					offset += uint64(len(str)) + 1
					logger.DLog("str: %s \n", str)
					if abbrev.Tag == DW_TAG_subprogram {
						if attr.Attr == DW_AT_name {
							dwarfFuncInfo.Name = str
						} else if attr.Attr == DW_AT_linkage_name {
							dwarfFuncInfo.LinkageName = str
						} else {
							panic("not name!")
						}
					}
					if abbrev.Tag == DW_TAG_formal_parameter {
						funcArg.Name = str
					}
					if abbrev.Tag == DW_TAG_variable {
						localVar.Name = str
					}
				case DW_FORM_block: // LEB128
					// TODO use Block info
					_, size := ReaduLEB128(debug_info[offset:])
					offset += uint64(size)
				case DW_FORM_block1: // 1byte(0～255)
					// TODO use Block info
					blockLen := debug_info[offset]
					offset += 1
					logger.TLog("Block1: len:%d\n", blockLen, blockLen)
					offset += uint64(blockLen)
				case DW_FORM_flag: // 1byte
					flagVal := debug_info[offset]
					offset += 1
					logger.TLog("flag: val:%d\n", flagVal)
				case DW_FORM_sdata:
					// TODO use constant
					_, size := ReadsLEB128(debug_info[offset:])
					offset += uint64(size)
				case DW_FORM_udata:
					// TODO use constant
					_, size := ReaduLEB128(debug_info[offset:])
					offset += uint64(size)
				case DW_FORM_ref1:
					val := debug_info[offset]
					refval := cuTop + uint64(val)
					logger.TLog("Attr: %s value:0x%02x\n", attrName, refval)
					offset += 1
				case DW_FORM_ref2:
					val, _ := binutil.FromLeToUInt16(debug_info[offset:])
					refval := cuTop + uint64(val)
					logger.TLog("Attr: %s value:0x%04x\n", attrName, refval)
					offset += 2
				case DW_FORM_ref4:
					val, _ := binutil.FromLeToUInt32(debug_info[offset:])
					refval := cuTop + uint64(val)
					logger.TLog("Attr: %s value:0x%04x\n", attrName, refval)
					if attr.Attr == DW_AT_specification {
						fTmp, exist := cppTmpFunc[refval]
						if exist {
							// take function reference
							dwarfFuncInfo = &fTmp
						} else {
							// TODO check func or variable
							logger.DLog("ref func not found")
						}
					} else if attr.Attr == DW_AT_sibling {
						siblingOffset = refval
					} else if attr.Attr == DW_AT_type {
						if abbrev.Tag == DW_TAG_formal_parameter {
							// TODO: TypeはDIEのオフセットになっているので別途解釈が必要
							funcArg.Type = refval
						}
					} else {
						fmt.Println("!!!! unhandled attr:%d", attr.Attr)
					}
					offset += 4
				case DW_FORM_sec_offset:
					switch attr.Attr {
					case DW_AT_stmt_list:
						// DW_AT_stmt_list is a section offset to the line number information
						// for this compilation unit
						tmp, _ := binutil.FromLeToUInt32(debug_info[offset:])
						cuLineInfoOffset = uint64(tmp)
						offset += uint64(unsafe.Sizeof(uint32(0)))
						logger.TLog("%s: 0x%02x\n", attrName, cuLineInfoOffset)
					case DW_AT_ranges:
						// A beginning address offset.
						// A range list entry consists of:
						// 1. A beginning address offset.
						//    This address offset has the size of an address and is relative to the applicable base address of the compilation unit referencing this range list.
						//    It marks the beginning of an address range.
						// 2. An ending address offset.
						//    This address offset again has the size of an address and is relative to the applicable base address of the compilation unit referencing this range list.
						//    It marks the first address past the end of the address range.
						//    The ending address must be greater than or equal to the beginning address.

						// P162 rangelistptr
						// This is an offset into the .debug_loc section (DW_FORM_sec_offset).
						// It consists of an offset from the beginning of the .debug_loc section to the first byte of the data making up the location list for the compilation unit.
						// It is relocatable in a relocatable object file, and relocated in an executable or shared object.
						// In the 32-bit DWARF format, this offset is a 4-byte unsigned value; in the 64-bit DWARF format, it is an 8-byte unsigned value (see Section 7.4).
						// TODO for 64bit impl
						var loclistptr uint64
						if cuh.DwarfFormat == DWARF_32BIT_FORMAT {
							tmp, _ := binutil.FromLeToUInt32(debug_info[offset:])
							loclistptr = uint64(tmp)
							offset += 4
						} else {
							loclistptr, _ = binutil.FromLeToUInt64(debug_info[offset:])
							offset += 8
						}
						logger.TLog("loclistptr:%x", loclistptr)
					case DW_AT_location:
						logger.TLog("%x:%s\n", abbrev.Tag, TagNameMap[abbrev.Tag])
						var loclistptr uint64
						if cuh.DwarfFormat == DWARF_32BIT_FORMAT {
							tmp, _ := binutil.FromLeToUInt32(debug_info[offset:])
							loclistptr = uint64(tmp)
							offset += 4
						} else {
							loclistptr, _ = binutil.FromLeToUInt64(debug_info[offset:])
							offset += 8
						}
						logger.TLog("loclistptr:%x", loclistptr)
						// GNU extensions
					case GNU_locviews:
						// TODO
						logger.TLog("%x:%s\n", abbrev.Tag, TagNameMap[abbrev.Tag])
						var loclistptr uint64
						if cuh.DwarfFormat == DWARF_32BIT_FORMAT {
							tmp, _ := binutil.FromLeToUInt32(debug_info[offset:])
							loclistptr = uint64(tmp)
							offset += 4
						} else {
							loclistptr, _ = binutil.FromLeToUInt64(debug_info[offset:])
							offset += 8
						}
						logger.TLog("loclistptr:%x", loclistptr)
					default:
						msg := fmt.Sprintf("unexpected attr:%d(%x)", attr.Attr, attr.Attr)
						panic(msg)
					}
				case DW_FORM_exprloc:
					logger.TLog("attr:%x,%s", attr.Attr, AttrNameMap[attr.Attr])
					// following size
					opSize, size := ReaduLEB128(debug_info[offset:])
					offset += uint64(size)

					length := int(opSize)
					for i := 0; i < length; {

						// dwarf exp OP Code
						ins := debug_info[offset]
						i++
						offset += 1
						if DW_OP_lo_user <= ins && ins <= DW_OP_hi_user {
							// TODO skip extensions
							offset += uint64(length - i)
							i += int(length - i)
							continue
						}

						switch ins {
						case DW_OP_addr:
							// size target specific
							addr, _ := binutil.FromLeToUInt64(debug_info[offset:])
							logger.TLog("DW_OP_addr:%x", addr)
							offset += uint64(curArrangeInfo.Header.AddressSize)
							i += int(curArrangeInfo.Header.AddressSize)
						case DW_OP_deref:
						case DW_OP_const1u:
							const1u := debug_info[offset]
							logger.TLog("DW_OP_const1u:%x", const1u)
							offset += 1
							i += 1
						case DW_OP_const1s:
							const1s := debug_info[offset]
							logger.TLog("DW_OP_const1s :%d", int8(const1s))
							offset += 1
							i += 1
						case DW_OP_const2u:
							const2u, _ := binutil.FromLeToUInt16(debug_info[offset:])
							logger.TLog("DW_OP_const2u :%d", const2u)
							offset += 2
							i += 2
						case DW_OP_const2s:
							const2s, _ := binutil.FromLeToInt16(debug_info[offset:])
							logger.TLog("DW_OP_const2s :%d", const2s)
							offset += 2
							i += 2
						case DW_OP_const4u:
							const4u, _ := binutil.FromLeToUInt32(debug_info[offset:])
							logger.TLog("DW_OP_const4u :%d", const4u)
							offset += 4
							i += 4
						case DW_OP_const4s:
							const4s, _ := binutil.FromLeToInt32(debug_info[offset:])
							logger.TLog("DW_OP_const4s :%d", const4s)
							offset += 4
							i += 4
						case DW_OP_const8u:
							const8u, _ := binutil.FromLeToUInt64(debug_info[offset:])
							logger.TLog("DW_OP_const8u :%d", const8u)
							offset += 8
							i += 8
						case DW_OP_const8s:
							const8s, _ := binutil.FromLeToInt64(debug_info[offset:])
							logger.TLog("DW_OP_const8s :%d", const8s)
							offset += 8
							i += 8
						case DW_OP_constu:
							constu, size := ReadsLEB128(debug_info[offset:])
							offset += uint64(size)
							i += size
							logger.TLog("DW_OP_constu:%d\n", constu)
						case DW_OP_consts:
							consts, size := ReadsLEB128(debug_info[offset:])
							offset += uint64(size)
							i += size
							logger.TLog("DW_OP_consts:%d\n", consts)
						case DW_OP_drop:
						case DW_OP_over:
						case DW_OP_swap:
						case DW_OP_abs:
						case DW_OP_and:
						case DW_OP_div:
						case DW_OP_minus:
						case DW_OP_mod:
						case DW_OP_mul:
						case DW_OP_neg:
						case DW_OP_not:
						case DW_OP_or:
						case DW_OP_plus:
						case DW_OP_plus_uconst:
							operand, size := ReaduLEB128(debug_info[offset:])
							offset += uint64(size)
							i += size
							logger.TLog("\toperand:%d\n", operand)
						case DW_OP_shl:
						case DW_OP_shr:
						case DW_OP_shra:
						case DW_OP_xor:
						case DW_OP_skip: // 0x2f
							operand, _ := binutil.FromLeToInt16(debug_info[offset:])
							offset += 2
							i += 2
							logger.TLog("\toperand:%d\n", operand)
						case DW_OP_bra: //  0x28
							operand, _ := binutil.FromLeToInt16(debug_info[offset:])
							offset += 2
							i += 2
							logger.TLog("\toperand:%d\n", operand)
						case DW_OP_eq: // = 0x29
						case DW_OP_ge: // = 0x2a
						case DW_OP_gt: // = 0x2b
						case DW_OP_le: // = 0x2c
						case DW_OP_lt: // = 0x2d
						case DW_OP_ne: // = 0x2e

						case DW_OP_fbreg:
							operand, size := ReadsLEB128(debug_info[offset:])
							offset += uint64(size)
							i += size
							logger.TLog("\toperand:%d\n", operand)
							if abbrev.Tag == DW_TAG_variable {
								if dwarfFuncInfo != nil {
									if dwarfFuncInfo.FrameBase == FRAME_TYPE_CFI {
										fde, _ := frameInfo.FDEs[dwarfFuncInfo.Addr]
										cie := frameInfo.CIEs[fde.CIEIdx]
										logger.TLog("CIE Id: %d\n", cie.CIE_id)
									} else {
										panic("!!!!")
									}
								} else {
									logger.TLog("DW_TAG_variable found, dwarfFuncInfo is nil\n")
								}
								localVar.Location.Offset = int32(operand)
							}
							if abbrev.Tag == DW_TAG_formal_parameter {
								// TODO: Location.Reg をCFIを元に初期化すべき
								funcArg.Location.Offset = int32(operand)
							}
						case DW_OP_call_frame_cfa:
							// TODO: フレームベースの種別だけでよいか？
							// → call_frame_cfa以外に何がある？
							dwarfFuncInfo.FrameBase = FRAME_TYPE_CFI
							// no operand
						case DW_OP_lit0:
							fallthrough
						case DW_OP_lit1:
							fallthrough
						case DW_OP_lit2:
							fallthrough
						case DW_OP_lit3:
							fallthrough
						case DW_OP_lit4:
							fallthrough
						case DW_OP_lit5:
							fallthrough
						case DW_OP_lit6:
							fallthrough
						case DW_OP_lit7:
							fallthrough
						case DW_OP_lit8:
							fallthrough
						case DW_OP_lit9:
							fallthrough
						case DW_OP_lit10:
							fallthrough
						case DW_OP_lit11:
							fallthrough
						case DW_OP_lit12:
							fallthrough
						case DW_OP_lit13:
							fallthrough
						case DW_OP_lit14:
							fallthrough
						case DW_OP_lit15:
							fallthrough
						case DW_OP_lit16:
							fallthrough
						case DW_OP_lit17:
							fallthrough
						case DW_OP_lit18:
							fallthrough
						case DW_OP_lit19:
							fallthrough
						case DW_OP_lit20:
							fallthrough
						case DW_OP_lit21:
							fallthrough
						case DW_OP_lit22:
							fallthrough
						case DW_OP_lit23:
							fallthrough
						case DW_OP_lit24:
							fallthrough
						case DW_OP_lit25:
							fallthrough
						case DW_OP_lit26:
							fallthrough
						case DW_OP_lit27:
							fallthrough
						case DW_OP_lit28:
							fallthrough
						case DW_OP_lit29:
							fallthrough
						case DW_OP_lit30:
							fallthrough
						case DW_OP_lit31:
							// TODO lit,
						case DW_OP_reg0:
							fallthrough
						case DW_OP_reg1:
							fallthrough
						case DW_OP_reg2:
							fallthrough
						case DW_OP_reg3:
							fallthrough
						case DW_OP_reg4:
							fallthrough
						case DW_OP_reg5:
							fallthrough
						case DW_OP_reg6:
							fallthrough
						case DW_OP_reg7:
							fallthrough
						case DW_OP_reg8:
							fallthrough
						case DW_OP_reg9:
							fallthrough
						case DW_OP_reg10:
							fallthrough
						case DW_OP_reg11:
							fallthrough
						case DW_OP_reg12:
							fallthrough
						case DW_OP_reg13:
							fallthrough
						case DW_OP_reg14:
							fallthrough
						case DW_OP_reg15:
							fallthrough
						case DW_OP_reg16:
							fallthrough
						case DW_OP_reg17:
							fallthrough
						case DW_OP_reg18:
							fallthrough
						case DW_OP_reg19:
							fallthrough
						case DW_OP_reg20:
							fallthrough
						case DW_OP_reg21:
							fallthrough
						case DW_OP_reg22:
							fallthrough
						case DW_OP_reg23:
							fallthrough
						case DW_OP_reg24:
							fallthrough
						case DW_OP_reg25:
							fallthrough
						case DW_OP_reg26:
							fallthrough
						case DW_OP_reg27:
							fallthrough
						case DW_OP_reg28:
							fallthrough
						case DW_OP_reg29:
							fallthrough
						case DW_OP_reg30:
							fallthrough
						case DW_OP_reg31:
							// TODO reg0 ~ reg31
						case DW_OP_breg0:
							fallthrough
						case DW_OP_breg1:
							fallthrough
						case DW_OP_breg2:
							fallthrough
						case DW_OP_breg3:
							fallthrough
						case DW_OP_breg4:
							fallthrough
						case DW_OP_breg5:
							fallthrough
						case DW_OP_breg6:
							fallthrough
						case DW_OP_breg7:
							fallthrough
						case DW_OP_breg8:
							fallthrough
						case DW_OP_breg9:
							fallthrough
						case DW_OP_breg10:
							fallthrough
						case DW_OP_breg11:
							fallthrough
						case DW_OP_breg12:
							fallthrough
						case DW_OP_breg13:
							fallthrough
						case DW_OP_breg14:
							fallthrough
						case DW_OP_breg15:
							fallthrough
						case DW_OP_breg16:
							fallthrough
						case DW_OP_breg17:
							fallthrough
						case DW_OP_breg18:
							fallthrough
						case DW_OP_breg19:
							fallthrough
						case DW_OP_breg20:
							fallthrough
						case DW_OP_breg21:
							fallthrough
						case DW_OP_breg22:
							fallthrough
						case DW_OP_breg23:
							fallthrough
						case DW_OP_breg24:
							fallthrough
						case DW_OP_breg25:
							fallthrough
						case DW_OP_breg26:
							fallthrough
						case DW_OP_breg27:
							fallthrough
						case DW_OP_breg28:
							fallthrough
						case DW_OP_breg29:
							fallthrough
						case DW_OP_breg30:
							fallthrough
						case DW_OP_breg31:
							// The single operand of the DW_OP_bregn operations provides a signed LEB128 offset
							// from the specified register.
							_, size := ReadsLEB128(debug_info[offset:])
							offset += uint64(size)
							i += size
						case DW_OP_deref_size:
							//operand := debug_info[offset:]
							offset++
							i += 1
						case DW_OP_implicit_value:
							length, size := ReaduLEB128(debug_info[offset:])
							offset += uint64(size)
							offset += length
							i += size
							i += int(length)
						case DW_OP_stack_value:
							// TODO
						default:
							msg := fmt.Sprintf("TODO Not decoded op 0x%02x\n", ins)
							panic(msg)
						}
					}
				case DW_FORM_flag_present:
					// flag exist
					logger.TLog("Attr: %s flag exists\n", attrName)
				case DW_FORM_line_strp:
					var strOffset uint64 = 0
					shLineStr := elfObj.GetSectionBinByName(".debug_line_str")
					if cuh.DwarfFormat == DWARF_32BIT_FORMAT {
						// 4byte
						tmp, _ := binutil.FromLeToUInt32(debug_info[offset:])
						offset += 4
						strOffset = (uint64)(tmp)
					} else {
						// 8byte
						tmp, _ := binutil.FromLeToUInt64(debug_info[offset:])
						offset += 8
						strOffset = tmp
					}
					name := binutil.GetString(shLineStr, strOffset)
					logger.DLog(name)
					if abbrev.Tag == DW_TAG_compile_unit {
						if attr.Attr == DW_AT_name {
							// for Rust
							if cuDbgInfo.IsRust() {
								idx := strings.LastIndex(name, "@")
								name = name[:idx-1]
							}
							cuDbgInfo.FileName = name
						} else if attr.Attr == DW_AT_comp_dir {
							cuDbgInfo.CompileDir = name
						} else {
							panic("---------------")
						}
					}
				case DW_FORM_implicit_const:
					if attr.Attr == DW_AT_decl_file {
						lineInfoHdr := offsetLineInfoMap[cuLineInfoOffset]
						fileName := lineInfoHdr.Files[attr.Const].Name
						logger.TLog("Attr: %s filename:%s\n", attrName, fileName)
					} else {
						logger.TLog("Attr: %s value:0x%02x\n", attrName, attr.Const)
					}
				default:
					fmt.Printf("Unknown Form:0x%x\n", attr.Form)
					panic("unknown")
				}
			}
			if abbrev.Tag == DW_TAG_formal_parameter {
				// Add argument to FuncInfo
				logger.DLog("Add Arg, Name:%s", funcArg.Name)
				if dwarfFuncInfo != nil {
					// TAGがsubroutine_typeの場合は関数情報は作成していない
					dwarfFuncInfo.Args = append(dwarfFuncInfo.Args, *funcArg)
				}
			}
			if abbrev.Tag == DW_TAG_variable {
				// Add local variable to FuncInfo
				logger.DLog("Add local Variable, Name:%s", localVar.Name)
				if dwarfFuncInfo != nil {
					// グローバル変数も variableとして定義されるため、関数の場合のみ追加
					dwarfFuncInfo.LocalVars = append(dwarfFuncInfo.LocalVars, *localVar)
				}
			}

			if abbrev.Tag == DW_TAG_subprogram {
				if dwarfFuncInfo.Name == "" {
					dbgFunc, exist := cuDbgInfo.Funcs[dwarfFuncInfo.Addr]
					if exist {
						logger.TLog("name:%s, addr:0x%X already registed\n", dbgFunc.Name, dwarfFuncInfo.Addr)
					} else {
						// TODO For Rust
						cppTmpFunc[uint64(entryOffset)] = *dwarfFuncInfo
						logger.DLog("addr:0x:%x function not found\n", dwarfFuncInfo.Addr)
						count++
						// TODO Comment out For Rust
						//os.Exit(2)
						continue
					}
				}
				if dwarfFuncInfo.Addr != 0 {
					// skip if addr not set(must be library function)
					logger.TLog("name:%s, linkageName:%s addr:0x%X\n", dwarfFuncInfo.Name, dwarfFuncInfo.LinkageName, dwarfFuncInfo.Addr)
					cuDbgInfo.Funcs[dwarfFuncInfo.Addr] = *dwarfFuncInfo
				} else {
					// addr not fixed, maybe c++ function delc, add tmpFuncs
					cppTmpFunc[uint64(entryOffset)] = *dwarfFuncInfo
				}
			}
			count++
		}
		dbgInfos = append(dbgInfos, cuDbgInfo)
	}

	return dbgInfos
}

func ReadLineInfo(bin []byte, elfObj elf.ElfObject) map[uint64]Dwarf32LineInfoHdr {
	offsetLineInfoHdrMap := map[uint64]Dwarf32LineInfoHdr{}
	var offset uint64 = 0
	var hdrOffset uint64 = 0
	lineInfoLen := uint64(len(bin))
	for hdrOffset < lineInfoLen {
		offset = hdrOffset
		lineInfoHdr := Dwarf32LineInfoHdr{}

		// TODO 4 or 8
		// unit_length initial length(4 or 8 bytes)
		tmp, _ := binutil.FromLeToUInt32(bin[offset:])
		offset += 4
		if tmp < 0xffffff00 {
			// 32-bit DWARF Format
			lineInfoHdr.UnitLength = uint64(tmp)
			lineInfoHdr.DwarfFormat = DWARF_32BIT_FORMAT
		} else {
			// 64-bit DWARF Format
			lineInfoHdr.UnitLength, _ = binutil.FromLeToUInt64(bin[offset:])
			lineInfoHdr.DwarfFormat = DWARF_64BIT_FORMAT
			offset += 8
		}

		// version uhalf
		lineInfoHdr.Version, _ = binutil.FromLeToUInt16(bin[offset:])
		offset += 2

		if 5 <= lineInfoHdr.Version {
			// DWARF Version 5 or later
			lineInfoHdr.AddressSize = bin[offset]
			offset += 1
			lineInfoHdr.SegmentSelectorSize = bin[offset]
			offset += 1
		}

		// header_length 32bit-DWARF/64bit-DWARF
		lineInfoHdr.HeaderLength, _ = binutil.FromLeToUInt32(bin[offset:])
		offset += 4

		// minimum_instruction_length ubyte
		lineInfoHdr.MinInstLength = bin[offset]
		offset += 1

		// maximum_operations_per_instruction ubyte
		if 4 <= lineInfoHdr.Version {
			lineInfoHdr.MaxInstLength = bin[offset]
			offset += 1
		}

		// default_is_stmt ubyte
		lineInfoHdr.DefaultIsStmt = bin[offset]
		offset += 1

		// line_base (sbyte)
		lineInfoHdr.LineBase = int8(bin[offset])
		offset += 1

		// line_range ubyte
		lineInfoHdr.LineRange = bin[offset]
		offset += 1

		// opcode_base ubyte
		// The number assigned to the first special opcode.
		lineInfoHdr.OpcodeBase = bin[offset]
		offset += 1

		// standard_opcode_lengths array of ubyte
		// This array specifies the number of LEB128 operands for each of the standard opcodes.
		// The first element of the array corresponds to the opcode whose value is 1, and
		// the last element corresponds to the opcode whose value is opcode_base - 1.
		lineInfoHdr.StdOpcodeLengths = []byte{}
		for i := 0; i < int(lineInfoHdr.OpcodeBase-1); i++ {
			lineInfoHdr.StdOpcodeLengths = append(lineInfoHdr.StdOpcodeLengths, bin[offset])
			offset++
		}

		if 5 <= lineInfoHdr.Version {
			// DWARF Version 5 or later
			lineInfoHdr.IncludeDirs = []string{}

			// directories
			lineInfoHdr.DirectoryEntryFormatCount = bin[offset]
			offset++

			// P156
			var sz int = 0
			for i := 0; i < (int)(lineInfoHdr.DirectoryEntryFormatCount); i++ {
				var EntryFmt EntryFormat
				EntryFmt.TypeCode, sz = ReaduLEB128(bin[offset:])
				offset += uint64(sz)
				EntryFmt.FormCode, sz = ReaduLEB128(bin[offset:])
				offset += uint64(sz)
				lineInfoHdr.DirectoryEntryFormats = append(lineInfoHdr.DirectoryEntryFormats, EntryFmt)
			}

			lineInfoHdr.DirectoriesCount, sz = ReaduLEB128(bin[offset:])
			offset += uint64(sz)

			for i := 0; i < (int)(lineInfoHdr.DirectoriesCount); i++ {
				for j := 0; j < (int)(lineInfoHdr.DirectoryEntryFormatCount); j++ {
					typeCode := lineInfoHdr.DirectoryEntryFormats[j].TypeCode
					formCode := lineInfoHdr.DirectoryEntryFormats[j].FormCode
					switch typeCode {
					case DW_LNCT_path:
						dirName := ""
						if formCode == DW_FORM_line_strp {
							// offset in the .debug_str, size follows Dwarf format(4 or 8)
							var strOffset uint64 = 0
							shLineStr := elfObj.GetSectionBinByName(".debug_line_str")
							if lineInfoHdr.DwarfFormat == DWARF_32BIT_FORMAT {
								// 4byte
								tmp, _ := binutil.FromLeToUInt32(bin[offset:])
								offset += 4
								strOffset = (uint64)(tmp)
							} else {
								// 8byte
								tmp, _ := binutil.FromLeToUInt64(bin[offset:])
								offset += 8
								strOffset = tmp
							}
							dirName = binutil.GetString(shLineStr, strOffset)
							logger.DLog(dirName)
						}
						lineInfoHdr.IncludeDirs = append(lineInfoHdr.IncludeDirs, dirName)
					default:
						panic("unknown")
					}
				}
			}

			// file names
			lineInfoHdr.FileNameEntryFormatCount = bin[offset]
			offset++

			for i := 0; i < (int)(lineInfoHdr.FileNameEntryFormatCount); i++ {
				var entryFmt EntryFormat
				entryFmt.TypeCode, sz = ReaduLEB128(bin[offset:])
				offset += uint64(sz)
				entryFmt.FormCode, sz = ReaduLEB128(bin[offset:])
				offset += uint64(sz)
				lineInfoHdr.FileNameEntryFormats = append(lineInfoHdr.FileNameEntryFormats, entryFmt)
			}

			lineInfoHdr.FileNamesCount, sz = ReaduLEB128(bin[offset:])
			offset += uint64(sz)

			for i := 0; i < (int)(lineInfoHdr.FileNamesCount); i++ {
				fileNameInfo := FileNameInfo{}
				var fileIdx uint64 = 0
				for j := 0; j < (int)(lineInfoHdr.FileNameEntryFormatCount); j++ {
					typeCode := lineInfoHdr.FileNameEntryFormats[j].TypeCode
					formCode := lineInfoHdr.FileNameEntryFormats[j].FormCode
					switch typeCode {
					case DW_LNCT_path:
						if formCode == DW_FORM_line_strp {
							// offset in the .debug_str, size follows Dwarf format(4 or 8)
							var strOffset uint64 = 0
							shDbgStr := elfObj.GetSectionBinByName(".debug_line_str")
							if lineInfoHdr.DwarfFormat == DWARF_32BIT_FORMAT {
								// 4byte
								tmp, _ := binutil.FromLeToUInt32(bin[offset:])
								offset += 4
								strOffset = (uint64)(tmp)
							} else {
								// 8byte
								tmp, _ := binutil.FromLeToUInt64(bin[offset:])
								offset += 8
								strOffset = tmp
							}
							fileNameInfo.Name = binutil.GetString(shDbgStr, strOffset)
							logger.DLog(fileNameInfo.Name)
						} else {
							panic("not implemented")
						}
					case DW_LNCT_directory_index:
						switch formCode {
						case DW_FORM_data1:
							fileIdx = (uint64)(bin[offset])
							offset++
						case DW_FORM_data2:
							tmp, _ := binutil.FromLeToUInt16(bin[offset:])
							fileIdx += (uint64)(tmp)
							offset += 2
						case DW_FORM_udata:
							fileIdx, sz = ReaduLEB128(bin[offset:])
							offset += uint64(sz)
						default:
							panic("unknown")
						}
						fileNameInfo.DirIdx = fileIdx

					default:
						panic("unknown")
					}
				}
				// TODO save fileIdx info
				lineInfoHdr.Files = append(lineInfoHdr.Files, fileNameInfo)
			}

			endOffset := hdrOffset + uint64(lineInfoHdr.UnitLength)
			if lineInfoHdr.DwarfFormat == DWARF_32BIT_FORMAT {
				endOffset += 4
			} else {
				endOffset += 8
			}

			fileName := lineInfoHdr.Files[0].Name
			if 0 < (endOffset - offset) {
				readLineNumberProgram(fileName, lineInfoHdr, bin, offset, endOffset, elfObj)
			}

		} else {
			// include_directories
			lineInfoHdr.IncludeDirs = []string{}
			for {
				dirName := binutil.GetString(bin[offset:], 0)
				sLen := len(dirName)
				if sLen == 0 {
					offset++
					break
				}
				offset += uint64(sLen + 1)
				lineInfoHdr.IncludeDirs = append(lineInfoHdr.IncludeDirs, dirName)
			}

			// file_names
			lineInfoHdr.Files = []FileNameInfo{}
			for {
				fileNameInfo := FileNameInfo{}

				// name
				fileNameInfo.Name = binutil.GetString(bin[offset:], 0)
				sLen := len(fileNameInfo.Name)
				if sLen == 0 {
					offset++
					break
				}
				offset += uint64(sLen + 1)

				// directory Idx
				var sz int
				fileNameInfo.DirIdx, sz = ReaduLEB128(bin[offset:])
				offset += uint64(sz)

				// last modified
				fileNameInfo.LastModified, sz = ReaduLEB128(bin[offset:])
				offset += uint64(sz)

				// file size
				fileNameInfo.Size, sz = ReaduLEB128(bin[offset:])
				offset += uint64(sz)

				lineInfoHdr.Files = append(lineInfoHdr.Files, fileNameInfo)
			}

			endOffset := hdrOffset + uint64(lineInfoHdr.UnitLength)
			if lineInfoHdr.DwarfFormat == DWARF_32BIT_FORMAT {
				endOffset += 4
			} else {
				endOffset += 8
			}

			fileName := lineInfoHdr.Files[0].Name
			if 0 < (endOffset - offset) {
				readLineNumberProgram(fileName, lineInfoHdr, bin, offset, endOffset, elfObj)
			}
		}

		offsetLineInfoHdrMap[hdrOffset] = lineInfoHdr
		hdrOffset += uint64(lineInfoHdr.UnitLength)
		if lineInfoHdr.DwarfFormat == DWARF_32BIT_FORMAT {
			hdrOffset += 4
		} else {
			hdrOffset += 8
		}
	}
	return offsetLineInfoHdrMap
}
func NewLnsm(defaultIsStmt uint8) LineNumberStateMachine {
	lnsm := LineNumberStateMachine{}
	lnsm.Address = 0
	lnsm.OpIndex = 0
	lnsm.File = 1
	lnsm.Line = 1
	lnsm.Column = 0
	lnsm.IsStmt = (defaultIsStmt == 1)
	lnsm.BasicBlock = false
	lnsm.PrologueEnd = false
	lnsm.EndSequence = false
	lnsm.Isa = 0
	return lnsm
}
func readLineNumberProgram(fileName string, lineInfoHdr Dwarf32LineInfoHdr, secBin []uint8, lnpStart uint64, lnpEnd uint64, elfObj elf.ElfObject) {
	lnpIns := secBin[lnpStart:lnpEnd]
	var length uint64 = uint64(len(lnpIns))
	var offset uint64 = 0
	var curFuncAddr uint64 = 0
	lnsm := NewLnsm(lineInfoHdr.DefaultIsStmt)

	var endOfSeq = false
	for offset < length {
		endOfSeq = false

		// read opecode
		opcode := lnpIns[offset]

		// for debug
		opOffset := lnpStart + offset
		dwLnsName, exist := dwLnsNameMap[opcode]
		if exist {
			logger.TLog("[%6x] opcode: %d(0x%x), %s", opOffset, opcode, opcode, dwLnsName)
		} else {
			logger.TLog("[%6x] opcode: %d(0x%x)", opOffset, opcode, opcode)
		}

		offset++
		switch opcode {
		case 0x00: // extended opcodes
			length, size := ReaduLEB128(lnpIns[offset:])
			offset += uint64(size)
			extendedOpcode := lnpIns[offset]
			offset++
			switch extendedOpcode {
			case DW_LNE_end_sequence:
				lnsm = NewLnsm(lineInfoHdr.DefaultIsStmt)
				//offset += length
				// break parse loop
				endOfSeq = true
			case DW_LNE_set_address:
				addrSize := length - 1
				if addrSize == 8 {
					address, _ := binutil.FromLeToUInt64(lnpIns[offset:])
					lnsm.Address = address
					curFuncAddr = address
				} else {
					address, _ := binutil.FromLeToUInt32(lnpIns[offset:])
					lnsm.Address = uint64(address)
					curFuncAddr = uint64(address)
				}
				offset += length - 1
			case DW_LNE_define_file:
				// TODO
				offset += length - 1
			case DW_LNE_set_discriminator:
				// TODO
				// Bug. gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)
				// DW_LNE_set_discriminator is defined DWARF4, but section header's DWARF version is 3...
				discriminator, size := ReaduLEB128(lnpIns[offset:])
				lnsm.Discriminator = discriminator
				offset += uint64(size)
			case DW_LNE_lo_user:
				// TODO
				offset += length - 1
			case DW_LNE_hi_user:
				// TODO
				offset += length - 1
			default:
				msg := fmt.Sprintf("Unexpected extended opcode:%d(0x%x)", extendedOpcode, extendedOpcode)
				panic(msg)
			}
		case DW_LNS_copy:
			if lnsm.IsStmt {
				addFuncAddrLineInfo(lineInfoHdr, lnsm, curFuncAddr, elfObj)
			}
			lnsm.BasicBlock = false
			lnsm.PrologueEnd = false
			lnsm.EpilogueBegin = false
		case DW_LNS_advance_pc:
			addrInc, size := ReaduLEB128(lnpIns[offset:])
			lnsm.Address += addrInc * uint64(lineInfoHdr.MinInstLength)
			offset += uint64(size)
		case DW_LNS_advance_line:
			lineInc, size := ReadsLEB128(lnpIns[offset:])
			lnsm.Line = uint64(int64(lnsm.Line) + lineInc)
			offset += uint64(size)
		case DW_LNS_set_file:
			fileIdx, size := ReaduLEB128(lnpIns[offset:])
			lnsm.File = fileIdx
			offset += uint64(size)
		case DW_LNS_set_column:
			// column set
			coperand, size := ReaduLEB128(lnpIns[offset:])
			lnsm.Column = coperand
			offset += uint64(size)
		case DW_LNS_negate_stmt:
			// no operand
			lnsm.IsStmt = !(lnsm.IsStmt)
		case DW_LNS_set_basic_block:
			// no operand
			lnsm.BasicBlock = true
		case DW_LNS_const_add_pc:
			// no operand
			// increment addres is same as special opcode.
			adjOpcode := opcode - lineInfoHdr.OpcodeBase
			addrInc := (adjOpcode / lineInfoHdr.LineRange) * lineInfoHdr.MinInstLength
			lnsm.Address = uint64(int64(lnsm.Address) + int64(addrInc))
		case DW_LNS_fixed_advance_pc:
			// The DW_LNS_fixed_advance_pc opcode takes a single uhalf (unencoded) operand
			// and adds it to the address register of the state machine and sets the op_index register to 0.
			address, _ := binutil.FromLeToUInt16(lnpIns[offset:])
			lnsm.Address = uint64(int64(lnsm.Address) + int64(address))
			lnsm.OpIndex = 0
			offset += 2
		case DW_LNS_set_prologue_end:
			lnsm.PrologueEnd = true
		case DW_LNS_set_epilogue_begin:
			lnsm.EpilogueBegin = true
		case DW_LNS_set_isa:
			_, size := ReadsLEB128(lnpIns[offset:])
			offset += uint64(size)
		default:
			// special opcode
			// no operand
			// See Dwarf3.pdf 6.2.5.1 Special Opcodes
			// opcode = (desired line increment - line_base) + (line_range * address advance) + opcode_base
			// address increment = (adjusted opcode / line_range) * minimim_instruction_length
			// line increment = line_base + (adjusted opcode % line_range)
			adjOpcode := opcode - lineInfoHdr.OpcodeBase
			addrInc := (adjOpcode / lineInfoHdr.LineRange) * lineInfoHdr.MinInstLength
			lineInc := lineInfoHdr.LineBase + int8((adjOpcode % lineInfoHdr.LineRange))
			lnsm.Line = uint64(int64(lnsm.Line) + int64(lineInc))

			// check function
			addr := uint64(int64(lnsm.Address) + int64(addrInc))
			lnsm.Address = addr
			lnsm.BasicBlock = false
			lnsm.PrologueEnd = false
			lnsm.EpilogueBegin = false
			curFuncAddr = lnsm.Address
			if lnsm.IsStmt {
				addFuncAddrLineInfo(lineInfoHdr, lnsm, curFuncAddr, elfObj)
			}
			logger.DLog("special opcode:0x%02X, address inc:%d, line inc:%d\n", opcode, addrInc, lineInc)
		}
	}

	if !endOfSeq {
		panic("Error DW_LNE_end_sequence not found")
	}
	return
}

func addFuncAddrLineInfo(lineInfoHdr Dwarf32LineInfoHdr, lnsm LineNumberStateMachine, funcAddr uint64, elfObj elf.ElfObject) {
	file := lineInfoHdr.Files[lnsm.File-1]
	funcIdx := elfObj.GetFuncIdxByAddr(funcAddr)
	if funcIdx < 0 {
		logger.DLog("function not exist in %s, funcAddr:0x%x\n", elfObj.GetPath, funcAddr)
		return
	}
	elfFuncInfo := elfObj.GetFuncsInfos()[funcIdx]
	elfFuncInfo.SrcDirName = ""
	elfFuncInfo.SrcFileName = file.Name
	lineAddr := elf.LineAddrInfo{}
	lineAddr.Line = lnsm.Line
	lineAddr.Addr = lnsm.Address
	lineAddr.IsStmt = lnsm.IsStmt

	if 5 <= lineInfoHdr.Version {
		// get src file info
		lineAddr.SrcDirName = lineInfoHdr.IncludeDirs[file.DirIdx]
		elfFuncInfo.SrcDirName = lineInfoHdr.IncludeDirs[file.DirIdx]
		elfFuncInfo.LineAddrs[lnsm.Line] = lineAddr
		elfObj.GetFuncsInfos()[funcIdx] = elfFuncInfo
	} else {
		if file.DirIdx < 1 {
			// TODO find src path...
		} else {
			// implemented at libray
			//lineAddr.IsLibrary = true

			// get src file info
			lineAddr.SrcDirName = lineInfoHdr.IncludeDirs[file.DirIdx-1]
			elfFuncInfo.SrcDirName = lineInfoHdr.IncludeDirs[file.DirIdx-1]
		}
		elfFuncInfo.LineAddrs[lnsm.Line] = lineAddr
		elfObj.GetFuncsInfos()[funcIdx] = elfFuncInfo
	}
}

func ShowLineInfoHdr(lineInfoHdr Dwarf32LineInfoHdr) {
	fmt.Printf("unit length                        : %d\n", lineInfoHdr.UnitLength)
	fmt.Printf("version                            : %d\n", lineInfoHdr.Version)
	fmt.Printf("header length                      : %d\n", lineInfoHdr.HeaderLength)
	fmt.Printf("minimum_instruction_length         : %d\n", lineInfoHdr.MinInstLength)
	fmt.Printf("maximum_instruction_length         : %d\n", lineInfoHdr.MaxInstLength)
	fmt.Printf("default_is_stmt                    : %d\n", lineInfoHdr.DefaultIsStmt)
	fmt.Printf("line_base                          : %d\n", lineInfoHdr.LineBase)
	fmt.Printf("line_range                         : %d\n", lineInfoHdr.LineRange)
	fmt.Printf("opcode_base                        : %d\n", lineInfoHdr.OpcodeBase)
	fmt.Printf("Opcodes:\n")
	for i := 0; i < 12; i++ {
		fmt.Printf("  [%2d] %2d arguments\n", i+1, lineInfoHdr.StdOpcodeLengths[i])
	}
	fmt.Printf("include directories:\n")
	for i := 0; i < len(lineInfoHdr.IncludeDirs); i++ {
		fmt.Printf("  [%2d]%s\n", i+1, lineInfoHdr.IncludeDirs[i])
	}
	fmt.Printf("files:\n")
	for i := 0; i < len(lineInfoHdr.Files); i++ {
		fmt.Printf("  [%2d] name: %s, dirIdx: %d, lastModified: %d, size: %d\n",
			i+1,
			lineInfoHdr.Files[i].Name,
			lineInfoHdr.Files[i].DirIdx,
			lineInfoHdr.Files[i].LastModified,
			lineInfoHdr.Files[i].Size)
	}
}
func NewDwarf32Cuh(debug_info []byte) Dwarf32CuHdr {
	cuh := Dwarf32CuHdr{}
	var offset uintptr = 0
	tmp, _ := binutil.FromLeToUInt32(debug_info[0:4])
	offset += 4
	if tmp < 0xFFFFFF00 {
		// 32-bit DWARF Format
		cuh.UnitLength = uint64(tmp)
		cuh.DwarfFormat = DWARF_32BIT_FORMAT
	} else {
		// 64-bit DWARF Format
		cuh.UnitLength, _ = binutil.FromLeToUInt64(debug_info[offset:])
		cuh.DwarfFormat = DWARF_64BIT_FORMAT
		offset += 8
	}

	size := unsafe.Sizeof(uint16(0))
	cuh.Version, _ = binutil.FromLeToUInt16(debug_info[offset:])
	offset += size
	if cuh.Version < 5 {
		// debug_abbrev_offset
		cuh.DebugAbbrevOffset, _ = binutil.FromLeToUInt32(debug_info[offset:])
		offset += 4

		// address_size
		size = unsafe.Sizeof(uint8(0))
		cuh.AddressSize = debug_info[offset]
		offset++
	} else {
		// DWARF 5 or later
		cuh.UnitType = debug_info[offset]
		offset++

		// address_size
		cuh.AddressSize = debug_info[offset]
		offset++

		// debug_abbrev_offset
		cuh.DebugAbbrevOffset, _ = binutil.FromLeToUInt32(debug_info[offset:])
		offset += 4

		switch cuh.UnitType {
		case DW_UT_compile, DW_UT_partial:
		case DW_UT_skeleton, DW_UT_split_compile:
			cuh.UnitID, _ = binutil.FromLeToUInt64(debug_info[offset:])
			offset += 8
		case DW_UT_type, DW_UT_split_type:
			cuh.TypeSignature, _ = binutil.FromLeToUInt64(debug_info[offset:])
			offset += 8
			cuh.TypeSignature, _ = binutil.FromLeToUInt64(debug_info[offset:])
			if cuh.DwarfFormat == DWARF_32BIT_FORMAT {
				tmp, _ = binutil.FromLeToUInt32(debug_info[offset:])
				cuh.TypeOffset = (uint64)(tmp)
				offset += 8
			} else {
				cuh.TypeOffset, _ = binutil.FromLeToUInt64(debug_info[offset:])
			}
		default:
			panic("not implemented")
		}
	}

	return cuh
}

type AbbrevAttr struct {
	Attr  uint64
	Form  uint64
	Const uint64 // DWARF5～
}

type Abbrev struct {
	Id          uint64
	Tag         uint64
	HasChildren bool
	Attrs       []AbbrevAttr
}

type LineNumberStateMachine struct {
	Address       uint64 // The program-counter value corresponding to a machine instruction generated by the compiler.
	OpIndex       uint64 // The index of the first operation is 0. For non-VLIW architectures, this register will always be 0.
	File          uint64 // the identity of the source file corresponding to a machine instruction.
	Line          uint64 // An unsigned integer indicating a source line number 1～ (The compiler may emit the value 0 in cases where an instruction cannot be attributed to any source line.)
	Column        uint64 // An unsigned integer indicating a column number within a source line. Columns are numbered beginning at 1. The value 0 is reserved to indicate that a statement begins at the “left edge” of the line.
	IsStmt        bool   // A boolean indicating that the current instruction is a recommended breakpoint location
	BasicBlock    bool   // A boolean indicating that the current instruction is the beginning of a basic block.
	EndSequence   bool   // A boolean indicating that the current address is that of the first byte after the end of a sequence of target machine instructions.
	PrologueEnd   bool   // A boolean indicating that the current address is one (of possibly many) where execution should be suspended for an entry breakpoint of a function.
	EpilogueBegin bool   // A boolean indicating that the current address is one (of possibly many) where execution should be suspended for an exit breakpoint of a function.
	Isa           uint64 // An unsigned integer whose value encodes the applicable instruction set architecture for the current instruction.
	Discriminator uint64 // An unsigned integer identifying the block to which the current instruction belongs.
}

func ShowAbbrevTbl(abbrevTbl []Abbrev) {
	for _, abbrev := range abbrevTbl {
		tagName, exist := TagNameMap[abbrev.Tag]
		if !exist {
			tagName = "TAG None"
		}
		fmt.Printf("id:%d, %s %t\n", abbrev.Id, tagName, abbrev.HasChildren)
		for _, attr := range abbrev.Attrs {
			attrName := AttrNameMap[attr.Attr]
			formName := FormNameMap[attr.Form]
			fmt.Printf("  Attr: %s(0x%02x), Form: %s(0x%02x)\n", attrName, attr.Attr, formName, attr.Form)
		}
	}
}

func ReadAbbrevTbl(bytes []byte) []Abbrev {
	abbrevTbl := []Abbrev{}
	len := len(bytes)
	pos := 0
	var id uint64
	var tag uint64
	var hasChildren byte
	var size int
	for pos < len {
		abbrev := Abbrev{}
		abbrev.Attrs = []AbbrevAttr{}
		id, size = ReaduLEB128(bytes[pos:])
		pos += size
		if id == 0 {
			// Abbreviations Tables end with an entry consisting of a 0 byte for the abbreviation code.
			break
		}
		tag, size = ReaduLEB128(bytes[pos:])
		pos += size
		hasChildren = bytes[pos]
		pos++
		abbrev.Id = id
		abbrev.Tag = tag
		abbrev.HasChildren = hasChildren == DW_CHILDREN_yes

		// Read Attributes
		for {
			var attrCode uint64
			var formCode uint64
			var Const uint64
			attrCode, size = ReaduLEB128(bytes[pos:])
			pos += size

			formCode, size = ReaduLEB128(bytes[pos:])
			pos += size
			if attrCode == 0 && formCode == 0 {
				break
			}

			// DWARF5 or later, FORM special case
			if formCode == DW_FORM_implicit_const {
				Const, size = ReaduLEB128(bytes[pos:])
				pos += size
			}

			attr := AbbrevAttr{Attr: attrCode, Form: formCode, Const: Const}
			logger.DLog("attr:%s", AttrNameMap[attr.Attr])

			abbrev.Attrs = append(abbrev.Attrs, attr)
		}
		abbrevTbl = append(abbrevTbl, abbrev)
	}
	return abbrevTbl
}

func ReaduLEB128(bytes []byte) (uint64, int) {
	len := len(bytes)
	pos := 0
	var val uint64 = 0
	var tmp uint64
	for pos < len {
		tmp = uint64(bytes[pos] & 0x7F)
		tmp = tmp << (7 * pos)
		val += tmp
		if bytes[pos]&0x80 == 0 {
			break
		}
		pos++
	}
	return val, pos + 1
}
func ReadsLEB128(bytes []byte) (int64, int) {
	len := len(bytes)
	pos := 0
	var val int64 = 0
	var tmp int64
	for pos < len {
		tmp = int64(bytes[pos] & 0x7F)
		tmp = tmp << (7 * pos)
		val += tmp
		if bytes[pos]&0x80 == 0 {
			if bytes[pos]&0x40 != 0 {
				// signed
				// TODO
				val |= ^0 << (7 * (pos + 1))
			}
			break
		}
		pos++
	}
	return val, pos + 1
}
