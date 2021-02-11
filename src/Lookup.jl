export search
export new_since
export add_filename!, add_missing_filename!, add_resource

struct Lookup
    ASNs::Dict{AutSysNum}{Vector{RPKINode}}
    filenames::Dict{String}{RPKINode}
    missing_files::Dict{String}{RPKINode} # split up between CER and MFT?

    resources_v6::IntervalTree{IPv6, IntervalValue{IPv6, RPKINode}}
    resources_v4::IntervalTree{IPv4, IntervalValue{IPv4, RPKINode}}

    pubpoints::Dict{String}{Pair{Int,Set{RPKINode}}}
    too_specific::Vector{RPKINode}
    invalid_signatures::Vector{RPKIObject{T} where T} # TODO refactor to RPKINode
    invalid_certs::Vector{RPKINode}
    valid_certs::Vector{RPKINode}
end
Lookup() = Lookup(Dict(), Dict(), Dict(),
                  IntervalTree{IPv6, IntervalValue{IPv6, RPKINode}}(),
                  IntervalTree{IPv4, IntervalValue{IPv4, RPKINode}}(),

                  Dict{String}{Pair{Int,Set{RPKINode}}}(),
                  Vector(), Vector(), Vector(), Vector())


add_resource(l::Lookup, ipr::IPRange{IPv6}, node::RPKINode) = push!(l.resources_v6, IntervalValue(ipr, node))
add_resource(l::Lookup, ipr::IPRange{IPv4}, node::RPKINode) = push!(l.resources_v4, IntervalValue(ipr, node))
add_resource(l::Lookup, iv::Interval{IPv6}, node::RPKINode) = push!(l.resources_v6, IntervalValue(iv.first, iv.last, node))
add_resource(l::Lookup, iv::Interval{IPv4}, node::RPKINode) = push!(l.resources_v4, IntervalValue(iv.first, iv.last, node))
add_resource(l::Lookup, from::IPv6, to::IPv6, node::RPKINode) = push!(l.resources_v6, IntervalValue(from, to, node))
add_resource(l::Lookup, from::IPv4, to::IPv4, node::RPKINode) = push!(l.resources_v4, IntervalValue(from, to, node))

function add_filename!(l::Lookup, fn::String, node::RPKINode)
    l.filenames[fn] = node
end
function add_missing_filename!(l::Lookup, fn::String, node::RPKINode)
    l.missing_files[fn] = node
end

function search(l::Lookup, asn::AutSysNum) :: Vector{RPKINode}
    get(l.ASNs, asn, AutSysNum[])
end

function search(l::Lookup, filename::AbstractString) :: Dict{String}{RPKINode}
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

function get_pubpoint(node::RPKINode) :: String
    if isnothing(node.obj)
        return "root"
    end
    return if node.obj.object isa CER
        (host, _) = split_scheme_uri(node.obj.object.pubpoint)
        host
    elseif node.obj.object isa MFT || node.obj.object isa CRL
        @assert node.parent.obj.object isa CER
        (host, _) = split_scheme_uri(node.parent.obj.object.pubpoint)
        host
    elseif node.obj.object isa ROA
        @assert node.parent.parent.obj.object isa CER
        (host, _) = split_scheme_uri(node.parent.parent.obj.object.pubpoint)
        host
    end
end


function remarks_in_subtree(tree::RPKINode) :: Vector{Pair{Remark, RPKINode}}
    tree |> @filter(!isnothing(_.obj)) |> @filter(!isnothing(_.obj.remarks)) |>
        @map([r => _ for r in _.obj.remarks]) |>
        Iterators.flatten |>
        collect
end

function remarks_per_repo(tree::RPKINode) :: Dict{String}{Vector{Pair{Remark, RPKINode}}}
    nodes::Vector{RPKINode} = tree |> @filter(!isnothing(_.obj)) |> @filter(!isnothing(_.obj.remarks)) |> collect
    res = Dict{String}{Vector{Pair{Remark, RPKINode}}}()
    for n in nodes
        pp = get_pubpoint(n)
        if !(pp in keys(res))
            res[pp] = []
        end
        for r in n.obj.remarks
            push!(res[pp], r => n)
        end
    end
   res 
end

function new_since(tree::RPKINode, tp::TimePeriod=Hour(1)) :: Vector{RPKINode}
    tree |>
    @filter(!isnothing(_.obj)) |>
    @filter(_.obj.object isa CER && _.obj.object.notBefore > now(UTC) - tp ||
            _.obj.object isa MFT && _.obj.object.this_update > now(UTC) - tp ||
            _.obj.object isa CRL && _.obj.object.this_update > now(UTC) - tp) |>
    collect
end

"""
    search(tree, ipr)


Find RPKINodes holding CERs or ROAs containing resources queried for. ROAs are
matched if the ipr matches resources on the EE, or in the VRPs.

"""
function search(tree::RPKINode, ipr::IPRange{T}, include_more_specific::Bool=false) :: Vector{RPKINode} where {T<:IPAddr} 
    search(tree, ipr.first, ipr.last, include_more_specific)
end


function search(tree::RPKINode, q1::T, q2::T, more_specific::Bool) :: Vector{RPKINode} where {T<:IPAddr} 
    if isnothing(tree.obj )
        @debug "isnothing, returning"
        return []
    end
    curobj = tree.obj.object
    res = []
    matches = if q1 isa IPv6
        collect(intersect(curobj.resources_v6, q1, q2))
    elseif q1 isa IPv4
        collect(intersect(curobj.resources_v4, q1, q2))
    else
        throw("illegal AFI")
    end
    if isempty(matches)
        return []
    end
    for match in matches
        if (match.first == q1 <= q2 == match.last)
            @debug "query exactly matches match"
            if !more_specific
                # we do not want to return results more specific than the query
                if curobj isa ROA
                    @debug "terminal case: exact match, isa ROA"
                    return [tree]
                else
                    @debug "terminal case: exact match, not a ROA"
                    return [tree, (search.(match.value, q1, q2, more_specific) |> Iterators.flatten |> collect)... ]
                end
            else
                #TODO
                #@debug "more_specific true, ... TODO "
                #in_sub = search.(match.value, q1, q2, more_specific) |> Iterators.flatten |> collect
                for c in (filter(v -> v isa RPKINode, match.value) |> unique) #Set(match.value)
                    Base.append!(res, search(c, q1, q2, more_specific))
                end
                if isempty(res)
                    @debug "returning [tree]", tree
                    return [tree]
                else
                    @debug "returning res", res
                    return res
                end
            end
        elseif (match.first < q1 <= q2 <= match.last) ||
            (match.first <= q1 <= q2 < match.last) ||
            (match.first < q1 <= q2 < match.last)
             @debug "query is more specific than match"
            if isempty(match.value)
                # this match points to no RPKINodes
                if (match.first, match.last) == extrema(IPRange("0/0")) ||
                    (match.first, match.last) == extrema(IPRange("::/0"))
                    @debug "matched on 0.0.0.0/0 or ::/0, ignoring"
                else
                    # this is the first less-specific that matches the query
                    # and with no RPKINodes to continue the search, this is our
                    # best result
                    @debug "no values to recurse into, pushing $(tree)"
                    push!(res, tree)
                end
            else
                @debug "notempty"
                if curobj isa Union{RootCER, CER}
                    #@debug "res pre:", res
                    for c in Set(match.value)
                        Base.append!(res, search(c, q1, q2, more_specific))
                    end
                    #@debug "res now:", res
                    if isempty(res) &&
                        !((match.first, match.last) == extrema(IPRange("0/0")) ||
                          (match.first, match.last) == extrema(IPRange("::/0")))
                        @debug "no results, pushing first less-specific", tree.obj.filename
                        push!(res, tree)
                    end
                end
            end
        else
            @debug "query is less specific than match", match, q1, q2
            if more_specific
                #for c in Set(match.value)
                push!(res, tree)
                for c in (filter(v -> v isa RPKINode, match.value) |> unique) #Set(match.value)
                    Base.append!(res, search(c, q1, q2, more_specific))
                end
            else
                @debug "defaulting to returning the first less-specific if no other results found.." 
                #@debug "current res", res
                push!(res, tree.parent.parent)
                #@debug "now res is", res
            end
            #TODO
        end

    end
    res |> unique
end

function search(l::Lookup, ipr::IPRange{T}, include_more_specific::Bool=true) :: Vector{RPKINode} where {T<:IPAddr} 
    search(l, ipr.first, ipr.last, include_more_specific)
end
function search(l::Lookup, q1::T, q2::T, include_more_specific::Bool) :: Vector{RPKINode} where {T<:IPAddr} 
    matches = if q1 isa IPv6
        intersect(l.resources_v6, Interval(q1, q2)) |> collect
    else
        intersect(l.resources_v4, Interval(q1, q2)) |> collect
    end
    # TODO improve, filter out /0
    matches = filter(m -> m.first != zero(typeof(q1)) , matches) 
    if !include_more_specific
        matches = filter(m -> m.first <= q1 <= q2 <= m.last , matches)
    end
    map(e->e.value, matches) |> unique
end
