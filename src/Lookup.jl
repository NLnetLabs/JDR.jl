export search

struct Lookup
    ASNs::Dict{AutSysNum}{Vector{RPKINode}}
    filenames::Dict{String}{Vector{RPKINode}}
    prefix_tree::PrefixTree{RPKINode}
    pubpoints::Dict{String}{RPKINode}
    too_specific::Set{RPKINode}
    invalid_signatures::Set{RPKIObject{T} where T}
    invalid_certs::Set{RPKINode}
    valid_certs::Set{RPKINode}
end
Lookup() = Lookup(Dict(), Dict(), PrefixTree{RPKINode}(), Dict(), Set(), Set(), Set(), Set())

function search(l::Lookup, asn::AutSysNum)
    if asn in keys(l.ASNs)
        l.ASNs[asn]
    else
        []
    end
end

# FIXME: do we need separate lookup trees for v6 and v4?
function search(l::Lookup, prefix::IPv4Net)
    values(firstparent(l.prefix_tree, prefix))
end

function search(l::Lookup, prefix::IPv6Net)
    values(firstparent(l.prefix_tree, prefix))
end

# TODO make a struct, e.g. ObjectFilename, for this?
function search(l::Lookup, filename::String) :: Dict{String}{Vector{RPKINode}}
    filter(fn->occursin(filename, first(fn)), l.filenames)
    #get(l.filenames, filename, 
    #if filename in keys(l.filenames)
    #    res = l.filenames[filename]
    #    @assert length(res) == 1
    #    first(res)
    #else
    #    nothing
    #end
end

function Base.show(io::IO, l::Lookup)
    println(io, "filenames: ", length(l.filenames))
    println(io, "ASNs: ", length(keys(l.ASNs)))
    println(io, "pubpoints: ", length(l.pubpoints))
    println(io, "too_specific: ", length(l.too_specific))
    println(io, "invalid_signatures: ", length(l.invalid_signatures))
    println(io, "invalid_certs: ", length(l.invalid_certs))
    println(io, "valid_certs: ", length(l.valid_certs))
end
