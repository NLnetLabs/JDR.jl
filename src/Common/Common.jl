module Common
using IntervalTrees
using Sockets

export split_scheme_uri, split_rrdp_path
export Remark, RemarkLevel, RemarkType, RemarkCounts, RemarkCounts_t, count_remarks
export remark_encodingIssue!, remark_ASN1Error!, remark_ASN1Issue!, remark_manifestIssue!, remark_missingFile!, remark_validityIssue!, remark_resourceIssue!, remark_loopIssue!
export @oid, oid_to_str


function split_scheme_uri(uri::String) :: Tuple{String, String}
    m = match(r"(rsync|https)://([^/]+)/(.*)", uri)
    (_, hostname::String, cer_fn::String) = m.captures
    (hostname, cer_fn)
end
function split_rrdp_path(url::String) :: Tuple{String, String}
    m = match(r"https://([^/]+)(/.*)", url)
    (hostname, cer_fn) = m.captures
    (hostname, cer_fn)
end



##############################
# Remarks and related
##############################

@enum RemarkLevel DBG INFO WARN ERR
@enum RemarkType EncodingIssue ASN1Issue ManifestIssue MissingFile ValidityIssue ResourceIssue LoopIssue

remarkTID = 0
resetRemarkTID() = global remarkTID = 0
struct Remark
    lvl::RemarkLevel
    type::Union{Nothing, RemarkType}
    msg::String
    tid::Int
end
Remark(lvl::RemarkLevel, msg::String) = Remark(lvl, nothing, msg, 0)
Remark(lvl::RemarkLevel, type::RemarkType, msg::String) = Remark(lvl, type, msg, 0)

# Helper for constructors:
const RemarkCounts_t = Dict{Union{RemarkLevel, RemarkType}, Int64}
RemarkCounts() = RemarkCounts_t()

function remark!(o::Any, lvl::RemarkLevel, type::RemarkType, msg::String)
	if isnothing(o.remarks)
        o.remarks = Vector{Remark}([Remark(lvl, type, msg)])
    else
        push!(o.remarks, Remark(lvl, type, msg))
    end
end

# WARN level helpers:
remark_encodingIssue!(o::Any, msg::String) = remark!(o, WARN, EncodingIssue, msg)
remark_ASN1Issue!(o::Any, msg::String) = remark!(o, WARN, ASN1Issue, msg)
# ERR level helpers:
remark_ASN1Error!(o::Any, msg::String) = remark!(o, ERR, ASN1Issue, msg)
remark_manifestIssue!(o::Any, msg::String) = remark!(o, ERR, ManifestIssue, msg)
remark_missingFile!(o::Any, msg::String) = remark!(o, ERR, MissingFile, msg)
remark_validityIssue!(o::Any, msg::String) = remark!(o, ERR, ValidityIssue, msg)
remark_resourceIssue!(o::Any, msg::String) = remark!(o, ERR, ResourceIssue, msg)
remark_loopIssue!(o::Any, msg::String) = remark!(o, ERR, LoopIssue, msg)

function count_remarks(o::T) :: RemarkCounts_t where {T<:Any}
    res = RemarkCounts()
    if !isnothing(o.remarks)
        for r in o.remarks
            res[r.lvl] = get(res, r.lvl, 0) + 1
            res[r.type] = get(res, r.type, 0) + 1
        end
    end
    res
end

import Base.+
function +(c1::RemarkCounts_t, c2::RemarkCounts_t) :: RemarkCounts_t
    mergewith(+, c1, c2)
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

function oid_to_str(raw::Vector{UInt8}) :: String
    # pre-fill with the 0, so we can overwrite it with the
    # actual object identifier after splitting up the first subidentifier
    subids = Int[0] 

    tmp = UInt32(0)
    for idx in (1:length(raw))
        tmp |= UInt32(raw[idx] & 0x7f)
        if raw[idx] & 0x80 == 0x80 # first bit set? then this is a multibyte subidentifier
            tmp <<= 7
        else
            push!(subids, tmp)
            tmp = UInt32(0)
        end
        idx =+ 1
    end

    # construct first subidentifier from first two object identifiers
    # subid = (first*40) + second
    if subids[2] >= 80
        subids[1] = 2
        subids[2] -= 80
    elseif subids[2] >= 40
        subids[1] = 1
        subids[2] -= 40
    else
        # is this possible?
        # x=0, y = subid[2] 
        # so actually we do not need to do anything
    end

    join(subids, ".") 
end


##############################
# AutSysNum and related
##############################

export AutSysNum, AutSysNumRange, AsIdsOrRanges, covered

struct AutSysNum
    asn::UInt32
end
function AutSysNum(s::AbstractString) 
    m = match(r"(ASN?)?(\d+)"i, s)
    if m === nothing
        @error "can not parse '$(s)' into AutSysNum"
        throw("AutSysNum parse error")
    else
        AutSysNum(parse(UInt32, m.captures[end]))
    end
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

##############################
# Prefix / IntervalTree related
##############################

export IPRange, prefixlen
include("IPRange.jl")

"""
    check_coverage(on_invalid::Function, parent::IntervalTree, child::IntervalTree)

Check intervals in child are a subset of those in parent.

If a child interval is not properly covered by the parent, the `on_invalid`
function is passed the improperly covered interval and executed. The function
can be used to log warnings, or take other actions.

"""
function check_coverage(
    on_invalid::Function,
    parent::IntervalTree{T,<:AbstractInterval{T}},
    child::IntervalTree{T,<:AbstractInterval{T}},
)::Bool where {T<:IPAddr,V}
    all_covered = true
    overlap = collect(intersect(parent, child))
    for (p, c) in overlap
        if !(p.first <= c.first <= c.last <= p.last)
            all_covered = false
            on_invalid(c)
        end
    end
    all_covered
end


function check_coverage(
    parent::IntervalTree{T,<:AbstractInterval{T}},
    child::IntervalTree{T,<:AbstractInterval{T}},
)::Bool where {T<:IPAddr,U}
    check_coverage(parent, child) do
    end
end


end # module
