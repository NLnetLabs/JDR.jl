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

function search(l::Lookup, prefix::T) :: Vector{RPKINode} where T<:IPNet
    if !isnothing(l.prefix_tree[prefix])
        # exact hit
        values(firstparent(l.prefix_tree, prefix))
    elseif !isnothing(subtree(l.prefix_tree, prefix))
        # more-specifics below this one
        values(subtree(l.prefix_tree, prefix))
    else
        # falling back to first less-specific
        fp = firstparent(l.prefix_tree, prefix)
        if !isnothing(fp)
            return fp.vals
        else
            return []
        end
    end
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
