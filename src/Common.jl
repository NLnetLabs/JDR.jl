module Common
using IPNets

export Remark, RemarkLevel, RemarkCounts, RemarkCounts_t, count_remarks
export remark!, dbg!, info!, warn!, err!
export @oid



##############################
# Remarks and related
##############################

@enum RemarkLevel DBG INFO WARN ERR

remarkTID = 0
resetRemarkTID() = global remarkTID = 0
struct Remark
    lvl::RemarkLevel
    msg::String
    tid::Int
end
Remark(lvl, msg) = Remark(lvl, msg, global remarkTID += 1)

## Example:
#struct MyObject
#    id::Integer
#    remarks::Vector{Remark}
#    remark_counts::Dict{Level, Integer}
#end
#MyObject(i::Integer) = MyObject(i, [], RemarkCounts())


# Helper for constructors:
const RemarkCounts_t = Dict{RemarkLevel, Int64}
RemarkCounts() = Dict(lvl => 0 for lvl in instances(RemarkLevel)) 

function remark!(o::Any, lvl::RemarkLevel, msg::String)
	if isnothing(o.remarks)
        o.remarks = Vector{Remark}([])
	end	
	push!(o.remarks, Remark(lvl, msg))
end

dbg!(o::Any, msg::String) 	= remark!(o, DBG, msg)
info!(o::Any, msg::String) 	= remark!(o, INFO, msg)
warn!(o::Any, msg::String) 	= remark!(o, WARN, msg)
err!(o::Any, msg::String)  	= remark!(o, ERR, msg)

function remark!(o::Any, msg::String)
    @warn "common.jl: remark!() is deprecated! defaulting to info!()" maxlog=10
    info!(o, msg)
end

function count_remarks(o::T) where {T<:Any}
    res = RemarkCounts()
    if !isnothing(o.remarks)
        for r in o.remarks
            res[r.lvl] += 1
        end
    end
    res
end

import Base.+
function +(c1::RemarkCounts_t, c2::RemarkCounts_t) :: RemarkCounts_t
    res = RemarkCounts()
    for lvl in instances(RemarkLevel)
        res[lvl] = c1[lvl] + c2[lvl]
    end
    res
end



##############################
# @oid TODO move to ASN1?
##############################

macro oid(s)
    ints = map(i -> parse(UInt32, i), split(s, '.'))
    res = UInt8[]
    for i in ints
        if i >= 128
            tmp = UInt8[0x00]
            idx = 1
            while i >= 128 # equal to i & 0x80 == 0x80
                tmp[idx] +=  i % 128
                push!(tmp, 0x80) # next byte, set the first bit
                i >>= 7
                idx += 1
            end
            tmp[idx] +=  i % 128
            Base.append!(res, reverse(tmp))

        else
            push!(res, convert(UInt8, i))
        end
    end
    # now create the first byte from the first two identifiers
    res2::Vector{UInt8} = if res[1] == 0x01
        #res2::Vector{UInt8} = 
        vcat(res[2] + 40, res[3:end])
    elseif res[1] == 0x02
        #res2::Vector{UInt8} = 
        vcat(res[2] + 80, res[3:end])
    elseif res[1] == 0x03
        #res2::Vector{UInt8} = 
        vcat(res[2] + 120, res[3:end])
    end
    
    res2
end


##############################
# AutSysNum and related
##############################

export AutSysNum, AutSysNumRange, AsIdsOrRanges, covered

struct AutSysNum
    asn::UInt32
end
struct AutSysNumRange
    first::AutSysNum
    last::AutSysNum
end
const AsIdsOrRanges = Vector{Union{AutSysNum,AutSysNumRange}}

AutSysNumRange(f::Integer, l::Integer) = AutSysNumRange(AutSysNum(f), AutSysNum(l))
covered(a::AutSysNum, b::AutSysNum) = a.asn == b.asn
covered(a::AutSysNum, r::AutSysNumRange) = a >= r.first && a <= r.last
covered(r1::AutSysNumRange, r2::AutSysNumRange) = r1.first >= r2.first && r1.last <= r2.last
covered(r::AutSysNumRange, a::AutSysNum) = r.first == a.asn == r.last 

import Base.isless
isless(a::AutSysNum, b::AutSysNum) = a.asn < b.asn
Base.show(io::IO, a::AutSysNum) = print(io, "AS", a.asn)
Base.show(io::IO, r::AutSysNumRange) = print(io, "$(r.first)..$(r.last)")
function covered(a::Union{AutSysNum,AutSysNumRange}, aior::AsIdsOrRanges) 
    for aor in aior
        if covered(a, aor)
            return true
        end
    end
    false
end
function covered(aior_a::AsIdsOrRanges, aior_b::AsIdsOrRanges)
    for aor in aior_a
        if !(covered(aor, aior_b))
             return false
         end
    end

   true 
end

const IPPrefix = IPNet
struct IPRange{T<:IPNet}
    first::T
    last::T
end

##############################
# IPPrefix and related
##############################

export IPPrefix, IPRange, IPPrefixesOrRanges, covered

const IPPrefixesOrRanges = Vector{Union{IPPrefix, IPRange{<:IPNet}}}
function covered(p::IPPrefix, p2::IPPrefix) 
    # workaround because IPNets has a known limitation wrt the extrema of /0's
    if p2.netmask == 0
        return true
    end
    #issubset(p, p2)
    p2[1] <= p[1] <= p[end] <= p2[end]
end
covered(p::IPPrefix, r::IPRange) = p >= r.first && p <= r.last
covered(r1::IPRange, r2::IPRange) = r2.first <= r1.first <= r1.last <= r2.last
covered(::IPv4Net, ::IPv6Net) = false
covered(::IPv6Net, ::IPv4Net) = false
covered(::IPv4Net, ::IPRange{IPv6Net}) = false
covered(::IPv6Net, ::IPRange{IPv4Net}) = false

function covered(r::IPRange{IPv4Net}, p::IPv4Net) 
    if p.netmask == 0
        return true
    end
    p[1] <= r.first[1] <= r.last[end] <= p[end]
end
function covered(r::IPRange{IPv6Net}, p::IPv6Net) 
    if p.netmask == 0
        return true
    end
    p[1] <= r.first[1] <= r.last[end] <= p[end]
end

covered(::IPRange{IPv6Net}, ::IPv4Net) = false
covered(::IPRange{IPv4Net}, ::IPv6Net) = false

covered(::IPRange{IPv6Net}, ::IPRange{IPv4Net}) = false
covered(::IPRange{IPv4Net}, ::IPRange{IPv6Net}) = false


function covered(p::IPPrefix, pors::IPPrefixesOrRanges) :: Bool
    any(covered(p, por) for por in pors)
end
function covered(r::IPRange, pors::IPPrefixesOrRanges) :: Bool
    any(covered(r, por) for por in pors)
end
const ALL_SPACE = IPPrefixesOrRanges([IPv4Net("0/0"), IPv6Net("::/0")])
function covered(pors_a::IPPrefixesOrRanges, pors_b::IPPrefixesOrRanges) :: Bool
    # TODO optimize: if 0/0 and ::/0 are in pors_b, return true
    if pors_b == ALL_SPACE
        @debug "optimized return"
        return true
    end
    for por in pors_a
        if !covered(por, pors_b)
            return false
        end
    end
    true
end



end # module
