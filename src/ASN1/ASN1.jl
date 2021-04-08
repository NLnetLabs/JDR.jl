module ASN1

include("ASN.jl")
using .ASN

# re-exports from ASN:
export Node, Tag
export tagisa, tagvalue, tagtype, tag_OID, tag_OIDs, tagis_contextspecific, childcount
export containAttributeTypeAndValue
export get_extensions, check_extensions

# re-exports from validation_common:
export bitstring_to_v4range, bitstring_to_v6range, bitstrings_to_v4range, bitstrings_to_v6range
export to_bigint


#reexports from ASN.jl
export istag # used in X509
export check_contextspecific,
    check_tag,
    check_value,
    check_OID,
    check_attribute


export DER
include("DER.jl")
end
