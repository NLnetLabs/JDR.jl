using IntervalTrees
using Sockets

####################
# IPRange
####################

struct IPRange{T} <: AbstractRange{T}
    first::T
    last::T
end
Base.length(r::IPRange{IPv4}) = Int64(UInt32(r.last) - UInt32(r.first) + 1)
Base.length(r::IPRange{IPv6}) = max(typemax(UInt128), Int128(UInt128(r.last) - UInt128(r.first) + 1))
Base.size(r::IPRange) = (length(r),)
Base.first(r::IPRange) = r.first
Base.last(r::IPRange) = r.last
Base.step(r::IPRange) = 1
Base.:+(a::IPv4, i::Integer) = IPv4(a.host + i)
Base.:+(a::IPv6, i::Integer) = IPv6(a.host + i)

function IPRange(a::IPv4, prefixlen::Int)
    _a = IPv4(a.host >> (32-prefixlen) << (32-prefixlen))
    IPRange(_a, IPv4(a.host | typemax(UInt32) >> prefixlen))
end
function IPRange(a::IPv6, prefixlen::Int)
    _a = IPv6(a.host >> (128-prefixlen) << (128-prefixlen))
    IPRange(_a, IPv6(a.host | typemax(UInt128) >> prefixlen))
end

function IPRange(s::String)
    if contains(s, ':')
        IPRange(IPv6, s)
    else
        IPRange(IPv4, s)
    end
end

function IPRange(t::Type{T}, s::String)  where {T<:IPAddr}
    parts = split(s, '/')
    first = t(parts[1])
    if length(parts) == 1
        IPRange(first, first)
    else
        IPRange(first, parse(Int, parts[2]))
    end
end

function Base.show(io::IO, r::IPRange{IPv4})
    r_size = r.last.host - r.first.host + 1
    if count_ones(r_size) == 1
        print(io, "$(r.first)/$(32 - Int(log2(r_size)))")
    else
        print(io, "$(r.first) .. $(r.last)")
    end
end
function Base.show(io::IO, r::IPRange{IPv6})
    r_size = r.last.host - r.first.host + 1
    if count_ones(r_size) == 1
        print(io, "$(r.first)/$(128 - Int(log2(r_size)))")
    else
        print(io, "$(r.first) .. $(r.last)")
    end
end

prefixlen(r::IPRange{IPv6}) :: Int =  128 - trunc(Int, log2(length(r)))
prefixlen(r::IPRange{IPv4}) :: Int =  32 - trunc(Int, log2(length(r)))



# IntervalTrees needs these:
Base.zero(::Type{IPv4}) = IPv4(0)
Base.zero(::Type{IPv6}) = IPv6(0)


function Base.string(i::IntervalValue{IPv4, T}) :: String where T
    i_size = i.last.host - i.first.host + 1
    if count_ones(i_size) == 1
         "$(i.first)/$(32 - Int(log2(i_size)))"
    else
        "$(i.first) .. $(i.last)"
    end
end
function Base.string(i::IntervalValue{IPv6, T}) :: String where T 
    if i.first.host == 0 && i.last.host == typemax(UInt128)
        return "::/0"
    end
    i_size = i.last.host - i.first.host + 1
    if count_ones(i_size) == 1
        "$(i.first)/$(128 - Int(log2(i_size)))"
    else
        "$(i.first) .. $(i.last)"
    end
end