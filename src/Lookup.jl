struct Lookup
    ASNs::Dict{AutSysNum}{Vector{RPKINode}}
    filenames::Dict{String}{Vector{RPKINode}}
    prefix_tree::PrefixTree{RPKINode}
    pubpoints::Dict{String}{RPKINode}
    too_specific::Set{RPKINode}
    invalid_signatures::Set{RPKIObject{T} where T}
end
Lookup() = Lookup(Dict(), Dict(), PrefixTree{RPKINode}(), Dict(), Set(), Set())

function lookup(l::Lookup, asn::AutSysNum)
    if asn in keys(l.ASNs)
        l.ASNs[asn]
    else
        []
    end
end

# FIXME: do we need separate lookup trees for v6 and v4?
function lookup(l::Lookup, prefix::IPv4Net)
    values(firstparent(l.prefix_tree, prefix))
end

function lookup(l::Lookup, prefix::IPv6Net)
    values(firstparent(l.prefix_tree, prefix))
end

# TODO make a struct, e.g. ObjectFilename, for this?
function lookup(l::Lookup, filename::String)
    if filename in keys(l.filenames)
        res = l.filenames[filename]
        @assert length(res) == 1
        first(res)
    else
        nothing
    end
end
