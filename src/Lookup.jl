using IPNets
using ...PrefixTrees
export search
export add_filename!, add_missing_filename!

struct Lookup
    ASNs::Dict{AutSysNum}{Vector{RPKINode}}
    filenames::Dict{String}{RPKINode}
    missing_files::Dict{String}{RPKINode} # split up between CER and MFT?
    prefix_tree_v6::PrefixTree{RPKINode}
    prefix_tree_v4::PrefixTree{RPKINode}
    pubpoints::Dict{String}{RPKINode}
    too_specific::Vector{RPKINode}
    invalid_signatures::Vector{RPKIObject{T} where T} # TODO refactor to RPKINode
    invalid_certs::Vector{RPKINode}
    valid_certs::Vector{RPKINode}
end
Lookup() = Lookup(Dict(), Dict(), Dict(),
                  PrefixTree{RPKINode}(),
                  PrefixTree{RPKINode}(),
                  Dict(), Vector(), Vector(), Vector(), Vector())

function add_filename!(l::Lookup, fn::String, node::RPKINode)
    l.filenames[fn] = node
end
function add_missing_filename!(l::Lookup, fn::String, node::RPKINode)
    l.missing_files[fn] = node
end

function search(l::Lookup, asn::AutSysNum) :: Vector{RPKINode}
    get(l.ASNs, asn, AutSysNum[])
end

function search(l::Lookup, prefix::IPv6Net) :: Set{RPKINode}
    if !isnothing(l.prefix_tree_v6[prefix])
        # exact hit
        Set(values(firstparent(l.prefix_tree_v6, prefix)))
    elseif !isnothing(subtree(l.prefix_tree_v6, prefix))
        # more-specifics below this one
        Set(values(subtree(l.prefix_tree_v6, prefix)))
    else
        # falling back to first less-specific
        fp = firstparent(l.prefix_tree_v6, prefix)
        if !isnothing(fp)
            return Set(fp.vals)
        else
            return []
        end
    end
end
function search(l::Lookup, prefix::IPv4Net) :: Set{RPKINode}
    if !isnothing(l.prefix_tree_v4[prefix])
        # exact hit
        Set(values(firstparent(l.prefix_tree_v4, prefix)))
    elseif !isnothing(subtree(l.prefix_tree_v4, prefix))
        # more-specifics below this one
        Set(values(subtree(l.prefix_tree_v4, prefix)))
    else
        # falling back to first less-specific
        fp = firstparent(l.prefix_tree_v4, prefix)
        if !isnothing(fp)
            return Set(fp.vals)
        else
            return []
        end
    end
end


#function search(l::Lookup, prefix::T) :: Set{RPKINode} where T<:IPNet
#    if !isnothing(l.prefix_tree[prefix])
#        # exact hit
#        Set(values(firstparent(l.prefix_tree, prefix)))
#    elseif !isnothing(subtree(l.prefix_tree, prefix))
#        # more-specifics below this one
#        Set(values(subtree(l.prefix_tree, prefix)))
#    else
#        # falling back to first less-specific
#        fp = firstparent(l.prefix_tree, prefix)
#        if !isnothing(fp)
#            return Set(fp.vals)
#        else
#            return []
#        end
#    end
#end

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

##############################
# Helpers 
##############################

using StatsBase
using Query

function remarks_in_subtree(tree::RPKINode) :: Vector{Pair{Remark, RPKINode}}
    tree |> @filter(!isnothing(_.obj)) |> @filter(!isnothing(_.obj.remarks)) |>
        @map([r => _ for r in _.obj.remarks]) |>
        Iterators.flatten |>
        collect
end

function remarks_per_repo(l::Lookup, repo::String) :: Vector{Pair{Remark, RPKINode}}
    if !(repo in keys(l.pubpoints))
        @error "$(repo) not in Lookup.pubpoints"
        return nothing
    end
    subtree = l.pubpoints[repo]
    remarks_in_subtree(subtree)
end

function remarktypes_per_repo(l::Lookup, repo::String) :: Dict{Common.RemarkType, Integer}
    remarks_per_repo(l, repo) |> @map(_[1].type) |> collect |> countmap
end
