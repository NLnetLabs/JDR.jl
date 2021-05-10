module BGP

using JDR.RPKICommon: AutSysNum, IPRange

using IntervalTrees: IntervalTree, IntervalValue, Interval, intersect
using Sockets: IPAddr


import JDR.RPKICommon: search

const MIN_NO_PEERS=Int(20)
const RISTree{T} = IntervalTree{T, IntervalValue{T, AutSysNum}} where {T<:IPAddr}
RISTree(ivs::Vector{IntervalValue{T,V}}) where {T,V} = RISTree{T}(ivs)

function ris_from_file(t::Type{T}, fn::String) :: RISTree{T} where {T<:IPAddr}
    intervals = IntervalValue{t, AutSysNum}[]
    for line in readlines(fn)
        if isempty(line) || line[1] == '%'
            continue
        end
        (origin, prefix, peers) = split(line, '\t')
        parse(Int,peers) < MIN_NO_PEERS && continue
        if line[1] == '{'
            # AS-SET, skipping
            continue
        end
        ipr = IPRange(t, prefix)
        push!(intervals, IntervalValue(ipr.first, ipr.last, AutSysNum(origin)))
    end
    sort!(unique!(intervals))
    IntervalTree{t, IntervalValue{t, AutSysNum}}(intervals)
end


function search(ris::RISTree{T}, asn::AutSysNum) :: RISTree{T} where {T<:IPAddr}
    filter(e -> e.value == asn , collect(IntervalValue{T, AutSysNum}, ris)) |> RISTree
end

function search(ris::RISTree{T}, ipr::IPRange{T}, include_more_specific::Bool=false) :: RISTree{T}  where {T<:IPAddr}
    q1, q2 = ipr.first, ipr.last
    matches = intersect(ris, Interval(q1, q2)) |> collect
    matches = filter(m -> m.first != zero(T) , matches) 
    if !include_more_specific
        matches = filter(m -> m.first <= q1 <= q2 <= m.last , matches)
    end
    matches |> unique |> RISTree
end

end
