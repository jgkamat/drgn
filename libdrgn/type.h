// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Type internals.
 *
 * See @ref TypeInternals.
 */

#ifndef DRGN_TYPE_H
#define DRGN_TYPE_H

#include <assert.h>

#include "drgn.h"
#include "hash_table.h"
#include "vector.h"

struct drgn_language;

/**
 * @ingroup Internals
 *
 * @defgroup TypeInternals Types
 *
 * Type internals.
 *
 * This provides internal helpers for creating and accessing types.
 * Additionally, standard C types need special handling for C's various operator
 * conversion rules, so this provides helpers for working with standard C types.
 *
 * @{
 */

/** Registered type finding callback in a @ref drgn_program. */
struct drgn_type_finder {
	/** The callback. */
	drgn_type_find_fn fn;
	/** Argument to pass to @ref drgn_type_finder::fn. */
	void *arg;
	/** Next callback to try. */
	struct drgn_type_finder *next;
};

DEFINE_HASH_SET_TYPE(drgn_dedupe_type_set, struct drgn_type *)

/** <tt>(type, member name)</tt> pair. */
struct drgn_member_key {
	struct drgn_type *type;
	const char *name;
	size_t name_len;
};

/** Type, offset, and bit field size of a type member. */
struct drgn_member_value {
	struct drgn_lazy_type *type;
	uint64_t bit_offset, bit_field_size;
};

#ifdef DOXYGEN
/**
 * @struct drgn_member_map
 *
 * Map of compound type members.
 *
 * The key is a @ref drgn_member_key, and the value is a @ref drgn_member_value.
 *
 * @struct drgn_type_set
 *
 * Set of types compared by address.
 */
#else
DEFINE_HASH_MAP_TYPE(drgn_member_map, struct drgn_member_key,
		      struct drgn_member_value)
DEFINE_HASH_SET_TYPE(drgn_type_set, struct drgn_type *)
#endif

/**
 * @defgroup LazyTypes Lazy types
 *
 * Lazily-evaluated types.
 *
 * The graph of types in a program can be very deep (and often cyclical), so
 * drgn lazily evaluates the types of compound type members and function
 * parameters.
 *
 * @{
 */

/**
 * Thunk which evaluates to a @ref drgn_qualified_type.
 *
 * This is used for @ref drgn_lazy_type.
 *
 * Note that the thunk callbacks take no additional arguments. A "closure" can
 * be created by embedding this structure in a structure containing the
 * necessary arguments; the closure type can then be accessed through a macro
 * like @c container_of().
 */
struct drgn_type_thunk {
	/** Program owning this thunk. */
	struct drgn_program *prog;
	/**
	 * Callback to evaluate this thunk to a @ref drgn_qualified_type.
	 *
	 * This should initialize the passed qualified type. If this succeeds,
	 * the thunk will then be freed with @ref drgn_type_thunk::free_fn().
	 * Otherwise, this may be called again.
	 */
	struct drgn_error *(*evaluate_fn)(struct drgn_type_thunk *,
					  struct drgn_qualified_type *);
	/**
	 * Callback to free this thunk.
	 *
	 * @ref drgn_type_thunk::evaluate_fn() may or may not have been called.
	 */
	void (*free_fn)(struct drgn_type_thunk *);
};

/**
 * Free a @ref drgn_type_thunk.
 *
 * @param[in] thunk Thunk to free.
 */
static inline void drgn_type_thunk_free(struct drgn_type_thunk *thunk)
{
	thunk->free_fn(thunk);
}

/**
 * Create a @ref drgn_lazy_type from a @ref drgn_type_thunk.
 *
 * @param[out] lazy_type Lazy type to initialize.
 * @param[in] thunk Thunk to wrap.
 */
static inline void drgn_lazy_type_init_thunk(struct drgn_lazy_type *lazy_type,
					     struct drgn_type_thunk *thunk)
{
	lazy_type->thunk = thunk;
	lazy_type->qualifiers = -1;
}

/**
 * Create a @ref drgn_lazy_type from a @ref drgn_type and qualifiers.
 *
 * @param[out] lazy_type Lazy type to initialize.
 * @param[in] type Type to wrap. May be @c NULL.
 * @param[in] qualifiers Type qualifiers. Must be 0 if type is @c NULL. Must not
 * be -1.
 */
static inline void
drgn_lazy_type_init_evaluated(struct drgn_lazy_type *lazy_type,
			      struct drgn_type *type,
			      enum drgn_qualifiers qualifiers)
{
	if (!type)
		assert(!qualifiers);
	assert(qualifiers != (enum drgn_qualifiers)-1);
	lazy_type->type = type;
	lazy_type->qualifiers = qualifiers;
}

/**
 * Get whether a @ref drgn_lazy_type has been evaluated.
 *
 * @param[in] lazy_type Lazy type to check.
 * @return Whether the lazy type is evaluated.
 */
static inline bool drgn_lazy_type_is_evaluated(struct drgn_lazy_type *lazy_type)
{
	return lazy_type->qualifiers != (enum drgn_qualifiers)-1;
}

/**
 * Evaluate a @ref drgn_lazy_type to a @ref drgn_qualified_type.
 *
 * If this succeeds, the lazy type is considered evaluated and future calls will
 * always succeed and return the cached result. If this fails, the lazy type
 * remains in a valid, unevaluated state.
 *
 * @param[in] lazy_type Lazy type to evaluate.
 * @param[out] ret Evaluated type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_lazy_type_evaluate(struct drgn_lazy_type *lazy_type,
					   struct drgn_qualified_type *ret);

/**
 * Free a @ref drgn_lazy_type.
 *
 * If the type has not been evaluted, this frees the @ref drgn_type_thunk.
 * Otherwise, this is a no-op.
 *
 * @param[in] lazy_type Lazy type to free.
 */
void drgn_lazy_type_deinit(struct drgn_lazy_type *lazy_type);

/** @} */

/**
 * @defgroup TypeCreation Type creation
 *
 * Creating type descriptors.
 *
 * These functions create type descriptors. They are valid for the lifetime of
 * the program that owns them.
 *
 * A few kinds of types have variable-length fields: structure, union, and class
 * types have members, enumerated types have enumerators, and function types
 * have parameters. These fields are constructed with a @em builder before
 * creating the type.
 *
 * @{
 */

/**
 * Get the void type for the given @ref drgn_language.
 *
 * The void type does not have any fields, so a program has a single type
 * descriptor per language to represent it. This function cannot fail.
 *
 * @param[in] prog Program owning type.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @p prog.
 */
struct drgn_type *drgn_void_type(struct drgn_program *prog,
				 const struct drgn_language *lang);

/**
 * Create an integer type.
 *
 * @param[in] prog Program owning type.
 * @param[in] name Name of the type. Not copied; must remain valid for the
 * lifetime of @p prog. Must not be @c NULL.
 * @param[in] size Size of the type in bytes.
 * @param[in] is_signed Whether the type is signed.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @p prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_int_type_create(struct drgn_program *prog,
					const char *name, uint64_t size,
					bool is_signed,
					const struct drgn_language *lang,
					struct drgn_type **ret);

/**
 * Create a boolean type.
 *
 * @param[in] prog Program owning type.
 * @param[in] name Name of the type. Not copied; must remain valid for the
 * lifetime of @p prog. Must not be @c NULL.
 * @param[in] size Size of the type in bytes.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @p prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_bool_type_create(struct drgn_program *prog,
					 const char *name, uint64_t size,
					 const struct drgn_language *lang,
					 struct drgn_type **ret);

/**
 * Create a floating-point type.
 *
 * @param[in] prog Program owning type.
 * @param[in] name Name of the type. Not copied; must remain valid for the
 * lifetime of @p prog. Must not be @c NULL.
 * @param[in] size Size of the type in bytes.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @p prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_float_type_create(struct drgn_program *prog,
					  const char *name, uint64_t size,
					  const struct drgn_language *lang,
					  struct drgn_type **ret);

/**
 * Create a complex type.
 *
 * @param[in] prog Program owning type.
 * @param[in] name Name of the type. Not copied; must remain valid for the
 * lifetime of @p prog. Must not be @c NULL.
 * @param[in] size Size of the type in bytes.
 * @param[in] real_type Corresponding real type. Must not be @c NULL and must be
 * a floating-point or integer type.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @p prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_complex_type_create(struct drgn_program *prog,
					    const char *name, uint64_t size,
					    struct drgn_type *real_type,
					    const struct drgn_language *lang,
					    struct drgn_type **ret);

DEFINE_VECTOR_TYPE(drgn_type_member_vector, struct drgn_type_member)
DEFINE_VECTOR_TYPE(drgn_template_parameter_vector, struct drgn_template_parameter)

/** Builder for members of a structure, union, or class type. */
struct drgn_compound_type_builder {
	struct drgn_program *prog;
	enum drgn_type_kind kind;
	struct drgn_type_member_vector members;
	struct drgn_template_parameter_vector templates;
};

/**
 * Initialize a @ref drgn_compound_type_builder.
 *
 * @param[in] kind One of @ref DRGN_TYPE_STRUCT, @ref DRGN_TYPE_UNION, or @ref
 * DRGN_TYPE_CLASS.
 */
void drgn_compound_type_builder_init(struct drgn_compound_type_builder *builder,
				     struct drgn_program *prog,
				     enum drgn_type_kind kind);

/**
 * Deinitialize a @ref drgn_compound_type_builder.
 *
 * Don't call this if @ref drgn_compound_type_create() succeeded.
 */
void
drgn_compound_type_builder_deinit(struct drgn_compound_type_builder *builder);

/**
 * Add a @ref drgn_type_member to a @ref drgn_compound_type_builder.
 *
 * On success, @p builder takes ownership of @p type.
 */
struct drgn_error *
drgn_compound_type_builder_add_member(struct drgn_compound_type_builder *builder,
				      struct drgn_lazy_type type,
				      const char *name, uint64_t bit_offset,
				      uint64_t bit_field_size);

/**
 * Add a @ref drgn_type_template_parameter to a drgn__type_builder.
 *
 * Accepts the prog (builder->prog) and template parameter vector
 * (&builder->templates) so it can be generalized.
 *
 * On success, @p builder takes ownership of @p type.
 */
struct drgn_error *
drgn_type_builder_add_template_parameter(struct drgn_program *prog,
					 struct drgn_template_parameter_vector *templates,
					 struct drgn_lazy_type type,
					 const char *name);

/**
 * Create a structure, union, or class type.
 *
 * On success, this takes ownership of @p builder.
 *
 * @param[in] builder Builder containing members. @c type and @c name of each
 * member must remain valid for the lifetime of @c builder->prog.
 * @param[in] tag Name of the type. Not copied; must remain valid for the
 * lifetime of @c builder->prog. May be @c NULL if the type is anonymous.
 * @param[in] size Size of the type in bytes. Ignored if type is incomplete.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @param[in] is_complete True if this type is complete.
 * @c builder->prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_compound_type_create(struct drgn_compound_type_builder *builder,
			  const char *tag, uint64_t size,
			  const struct drgn_language *lang,
			  bool is_complete,
			  struct drgn_type **ret);

DEFINE_VECTOR_TYPE(drgn_type_enumerator_vector, struct drgn_type_enumerator)

/** Builder for enumerators of an enumerated type. */
struct drgn_enum_type_builder {
	struct drgn_program *prog;
	struct drgn_type_enumerator_vector enumerators;
};

/** Initialize a @ref drgn_enum_type_builder. */
void drgn_enum_type_builder_init(struct drgn_enum_type_builder *builder,
				 struct drgn_program *prog);

/**
 * Deinitialize a @ref drgn_enum_type_builder.
 *
 * Don't call this if @ref drgn_enum_type_create() succeeded.
 */
void drgn_enum_type_builder_deinit(struct drgn_enum_type_builder *builder);

/**
 * Add a @ref drgn_type_enumerator with a signed value to a @ref
 * drgn_enum_type_builder.
 */
struct drgn_error *
drgn_enum_type_builder_add_signed(struct drgn_enum_type_builder *builder,
				  const char *name, int64_t svalue);

/**
 * Add a @ref drgn_type_enumerator with an unsigned value to a @ref
 * drgn_enum_type_builder.
 */
struct drgn_error *
drgn_enum_type_builder_add_unsigned(struct drgn_enum_type_builder *builder,
				    const char *name, uint64_t uvalue);

/**
 * Create an enumerated type.
 *
 * On success, this takes ownership of @p builder.
 *
 * @param[in] builder Builder containing enumerators. @c name of each enumerator
 * must remain valid for the lifetime of @c builder->prog.
 * @param[in] tag Name of the type. This string is not copied. It may be @c NULL
 * if the type is anonymous.
 * @param[in] compatible_type Type compatible with this enumerated type. Must be
 * an integer type.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @c builder->prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_enum_type_create(struct drgn_enum_type_builder *builder,
					 const char *tag,
					 struct drgn_type *compatible_type,
					 const struct drgn_language *lang,
					 struct drgn_type **ret);

/**
 * Create an incomplete enumerated type.
 *
 * @c compatible_type is set to @c NULL and @c num_enumerators is set to zero.
 *
 * @param[in] prog Program owning type.
 * @param[in] tag Name of the type. Not copied; must remain valid for the
 * lifetime of @p prog. May be @c NULL if the type is anonymous.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @p prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_incomplete_enum_type_create(struct drgn_program *prog, const char *tag,
				 const struct drgn_language *lang,
				 struct drgn_type **ret);

/**
 * Create a typedef type.
 *
 * @param[in] prog Program owning type.
 * @param[in] name Name of the type. Not copied; must remain valid for the
 * lifetime of @p prog. Must not be @c NULL.
 * @param[in] aliased_type Type aliased by the typedef.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @p prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_typedef_type_create(struct drgn_program *prog, const char *name,
			 struct drgn_qualified_type aliased_type,
			 const struct drgn_language *lang,
			 struct drgn_type **ret);

/**
 * Create a pointer type.
 *
 * @param[in] prog Program owning type.
 * @param[in] referenced_type Type referenced by the pointer type.
 * @param[in] size Size of the type in bytes.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @p prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_pointer_type_create(struct drgn_program *prog,
			 struct drgn_qualified_type referenced_type,
			 uint64_t size, const struct drgn_language *lang,
			 struct drgn_type **ret);

/**
 * Create an array type.
 *
 * @param[in] prog Program owning type.
 * @param[in] element_type Type of an element in the array type.
 * @param[in] length Number of elements in the array type.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @p prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_array_type_create(struct drgn_program *prog,
		       struct drgn_qualified_type element_type,
		       uint64_t length, const struct drgn_language *lang,
		       struct drgn_type **ret);

/**
 * Create an incomplete array type.
 *
 * @c length is set to zero.
 *
 * @param[in] prog Program owning type.
 * @param[in] element_type Type of an element in the array type.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @p prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_incomplete_array_type_create(struct drgn_program *prog,
				  struct drgn_qualified_type element_type,
				  const struct drgn_language *lang,
				  struct drgn_type **ret);

DEFINE_VECTOR_TYPE(drgn_type_parameter_vector, struct drgn_type_parameter)

/** Builder for parameters of a function type. */
struct drgn_function_type_builder {
	struct drgn_program *prog;
	struct drgn_type_parameter_vector parameters;
	struct drgn_template_parameter_vector templates;
};

/** Initialize a @ref drgn_function_type_builder. */
void drgn_function_type_builder_init(struct drgn_function_type_builder *builder,
				     struct drgn_program *prog);

/**
 * Deinitialize a @ref drgn_function_type_builder.
 *
 * Don't call this if @ref drgn_function_type_create() succeeded.
 */
void
drgn_function_type_builder_deinit(struct drgn_function_type_builder *builder);

/**
 * Add a @ref drgn_type_parameter to a @ref drgn_function_type_builder.
 *
 * On success, @p builder takes ownership of @p type.
 */
struct drgn_error *
drgn_function_type_builder_add_parameter(struct drgn_function_type_builder *builder,
					 struct drgn_lazy_type type,
					 const char *name);

/**
 * Add a @ref drgn_type_template_parameter to a @ref drgn_function_type_builder.
 *
 * On success, @p builder takes ownership of @p type.
 */
struct drgn_error *
drgn_function_type_builder_add_template_parameter(struct drgn_function_type_builder *builder,
						  struct drgn_lazy_type type,
						  const char *name);

/**
 * Create a function type.
 *
 * On success, this takes ownership of @p builder.
 *
 * @param[in] builder Builder containing parameters. @c type and @c name of each
 * parameter must remain valid for the lifetime of @c builder->prog.
 * @param[in] return_type Type returned by the function type.
 * @param[in] is_variadic Whether the function type is variadic.
 * @param[in] lang Language of the type or @c NULL for the default language of
 * @c builder->prog.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_function_type_create(struct drgn_function_type_builder *builder,
			  struct drgn_qualified_type return_type,
			  bool is_variadic, const struct drgn_language *lang,
			  struct drgn_type **ret);

/** @} */

/** Mapping from @ref drgn_type_kind to the spelling of that kind. */
extern const char * const drgn_type_kind_spelling[];

/**
 * Parse the name of an unqualified primitive C type.
 *
 * @return The type, or @ref DRGN_NOT_PRIMITIVE_TYPE if @p s is not the name of
 * a primitive C type.
 */
enum drgn_primitive_type c_parse_specifier_list(const char *s);

/**
 * Get the type of a @ref drgn_type with all typedefs removed.
 *
 * I.e., the underlying type is the aliased type of the type if it is a typedef,
 * recursively.
 */
static inline struct drgn_type *drgn_underlying_type(struct drgn_type *type)
{
	struct drgn_type *underlying_type;

	underlying_type = type;
	while (drgn_type_kind(underlying_type) == DRGN_TYPE_TYPEDEF)
		underlying_type = drgn_type_type(underlying_type).type;
	return underlying_type;
}

/**
 * Get whether an enumerated type is signed.
 *
 * This is true if and only if the compatible integer type is signed.
 *
 * @param[in] type Enumerated type. It must be complete.
 */
static inline bool drgn_enum_type_is_signed(struct drgn_type *type)
{
	assert(type->_private.type);
	return drgn_type_is_signed(type->_private.type);
}

/**
 * Get whether a type is anonymous (i.e., the type has no name).
 *
 * This may be @c false for structure, union, class, and enum types. Otherwise,
 * it is always true.
 */
static inline bool drgn_type_is_anonymous(struct drgn_type *type)
{
	switch (drgn_type_kind(type)) {
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS:
	case DRGN_TYPE_ENUM:
		return !drgn_type_tag(type);
	default:
		return false;
	}
}

/**
 * Returned whether a @ref drgn_type is an integer type.
 *
 * This is true for integer, boolean, and enumerated types, as well typedefs
 * with an underlying type of one of those.
 */
bool drgn_type_is_integer(struct drgn_type *type);

/**
 * Return whether a @ref drgn_type is an arithmetic type.
 *
 * This is true for integer types (see @ref drgn_type_is_integer()) as well as
 * floating-point types and equivalent typedefs.
 */
bool drgn_type_is_arithmetic(struct drgn_type *type);

/**
 * Return whether a @ref drgn_type is a scalar type.
 *
 * This is true for arithmetic types (see @ref drgn_type_is_arithmetic()) as
 * well as pointer types and equivalent typedefs.
 */
bool drgn_type_is_scalar(struct drgn_type *type);

/**
 * Get the size of a type in bits.
 *
 * This is the same as multplying the result of @ref drgn_type_sizeof() by 8
 * except that it handles overflow.
 */
struct drgn_error *drgn_type_bit_size(struct drgn_type *type,
				      uint64_t *ret);

/** Get the appropriate @ref drgn_object_kind for a @ref drgn_type. */
enum drgn_object_kind drgn_type_object_kind(struct drgn_type *type);

/** Initialize type-related fields in a @ref drgn_program. */
void drgn_program_init_types(struct drgn_program *prog);
/** Deinitialize type-related fields in a @ref drgn_program. */
void drgn_program_deinit_types(struct drgn_program *prog);

/**
 * Find a parsed type in a @ref drgn_program.
 *
 * This should only be called by implementations of @ref
 * drgn_language::find_type()
 *
 * @param[in] kind Kind of type to find. Must be @ref DRGN_TYPE_STRUCT, @ref
 * DRGN_TYPE_UNION, @ref DRGN_TYPE_CLASS, @ref DRGN_TYPE_ENUM, or @ref
 * DRGN_TYPE_TYPEDEF.
 * @param[in] name Name of the type.
 * @param[in] name_len Length of @p name in bytes.
 * @param[in] filename See @ref drgn_program_find_type().
 * @param[out] ret Returned type.
 * @return @c NULL on success, &@ref drgn_not_found if the type wasn't found,
 * non-@c NULL on other error.
 */
struct drgn_error *
drgn_program_find_type_impl(struct drgn_program *prog,
			    enum drgn_type_kind kind, const char *name,
			    size_t name_len, const char *filename,
			    struct drgn_qualified_type *ret);

/** Find a primitive type in a @ref drgn_program. */
struct drgn_error *
drgn_program_find_primitive_type(struct drgn_program *prog,
				 enum drgn_primitive_type type,
				 struct drgn_type **ret);

/**
 * Find the type, offset, and bit field size of a type member.
 *
 * This matches the members of the type itself as well as the members of any
 * unnamed members of the type.
 *
 * This caches all members of @p type for subsequent calls.
 *
 * @param[in] type Compound type to search in.
 * @param[in] member_name Name of member.
 * @param[in] member_name_len Length of @p member_name
 * @param[out] ret Returned member information.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_find_member(struct drgn_program *prog,
					    struct drgn_type *type,
					    const char *member_name,
					    size_t member_name_len,
					    struct drgn_member_value **ret);

/** @} */

#endif /* DRGN_TYPE_H */
