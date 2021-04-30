module BGP

using JDR.Common

using IntervalTrees
using Sockets

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


function search(ris::RISTree, asn::AutSysNum) :: RISTree 
    filter(e -> e.value == asn , collect(typeof(first(ris)), ris)) |> RISTree
end

end
