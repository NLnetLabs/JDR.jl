using IPNets
using ...PrefixTrees
export search
export add_filename!, add_missing_filename!

struct Lookup
    ASNs::Dict{AutSysNum}{Vector{RPKINode}}
    filenames::Dict{String}{RPKINode}
    missing_files::Dict{String}{RPKINode} # split up between CER and MFT?
    prefix_tree::PrefixTree{RPKINode}
    pubpoints::Dict{String}{RPKINode}
    too_specific::Set{RPKINode}
    invalid_signatures::Set{RPKIObject{T} where T}
    invalid_certs::Set{RPKINode}
    valid_certs::Set{RPKINode}
end
Lookup() = Lookup(Dict(), Dict(), Dict(), PrefixTree{RPKINode}(), Dict(), Set(), Set(), Set(), Set())

function add_filename!(l::Lookup, fn::String, node::RPKINode)
    l.filenames[fn] = node
end
function add_missing_filename!(l::Lookup, fn::String, node::RPKINode)
    l.missing_files[fn] = node
end

function search(l::Lookup, asn::AutSysNum) :: Vector{RPKINode}
    get(l.ASNs, asn, AutSysNum[])
end

# FIXME: do we need separate lookup trees for v6 and v4?
function search(l::Lookup, prefix::IPv4Net)
    values(firstparent(l.prefix_tree, prefix))
end

function search(l::Lookup, prefix::IPv6Net)
    values(firstparent(l.prefix_tree, prefix))
end

function search(l::Lookup, filename::String) :: Dict{String}{RPKINode}
    filter(fn->occursin(filename, first(fn)), l.filenames)
end

function Base.show(io::IO, l::Lookup)
    println(io, "filenames: ", length(l.filenames))
    println(io, "missing files: ", length(l.missing_files))
    println(io, "pubpoints: ", length(l.pubpoints))
    println(io, "ASNs: ", length(keys(l.ASNs)))
    println(io, "too_specific: ", length(l.too_specific))
    println(io, "invalid_signatures: ", length(l.invalid_signatures))
    println(io, "invalid_certs: ", length(l.invalid_certs))
    println(io, "valid_certs: ", length(l.valid_certs))
end
