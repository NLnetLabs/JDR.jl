####################
# IPRange
####################

"""
    IPRange{T<:IPAddr}

Describes an IP prefix or range by only storing the `first` and `last`
`Sockets.IPAddr`.
"""
struct IPRange{T} <: AbstractRange{T}
    first::T
    last::T
end

Base.length(r::IPRange{IPv4}) = Int64(UInt32(r.last) - UInt32(r.first) + 1)
Base.length(r::IPRange{IPv6}) = if r.first == IPv6(0) && r.last == IPv6(typemax(UInt128))
    typemax(UInt128)
else
    UInt128(r.last) - UInt128(r.first) + 1
end
Base.size(r::IPRange) = (length(r),)
Base.first(r::IPRange) = r.first
Base.last(r::IPRange) = r.last
Base.step(r::IPRange) = 1
Base.:+(a::IPv4, i::Integer) = IPv4(a.host + i)
Base.:+(a::IPv6, i::Integer) = IPv6(a.host + i)

"""
    IPRange(a::{IPv6}, prefixlen::Int)
    IPRange(a::{IPv4}, prefixlen::Int)

Create IPRange{IPv6/IPv4} from address and prefixlen

    IPRange(s::AbstractString)

Create an IPRange from the string representation, i.e.

```julia-repl
IPRange("1.2.3.0/24")
1.2.3.0/24
julia> IPRange("2001:db8::/32")
2001:db8::/32
```
"""
function IPRange(a::IPv4, prefixlen::Int)
    _a = IPv4(a.host >> (32-prefixlen) << (32-prefixlen))
    IPRange(_a, IPv4(a.host | typemax(UInt32) >> prefixlen))
end

function IPRange(a::IPv6, prefixlen::Int)
    _a = IPv6(a.host >> (128-prefixlen) << (128-prefixlen))
    IPRange(_a, IPv6(a.host | typemax(UInt128) >> prefixlen))
end

function IPRange(s::AbstractString)
    if contains(s, ':')
        IPRange(IPv6, s)
    else
        IPRange(IPv4, s)
    end
end

function IPRange(t::Type{T}, s::AbstractString)  where {T<:IPAddr}
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
    if r.first.host == 0 && r.last.host == typemax(UInt128)
        print(io, "::/0")
    elseif count_ones(r_size) == 1
        print(io, "$(r.first)/$(128 - Int(log2(r_size)))")
    else
        print(io, "$(r.first) .. $(r.last)")
    end
end

"""
    prefixlen(r::IPRange{IPv6})
    prefixlen(r::IPRange{IPv4})

Returns the prefix length of an [`IPRange`](@ref).
"""
prefixlen(r::IPRange{IPv6}) :: Int =  128 - trunc(Int, log2(length(r)))
prefixlen(r::IPRange{IPv4}) :: Int =  32 - trunc(Int, log2(length(r)))



# IntervalTrees needs these:
Base.zero(::Type{IPv4}) = IPv4(0)
Base.zero(::Type{IPv6}) = IPv6(0)


Base.string(i::IntervalValue{IPv6, T}) where T = string(IPRange{IPv6}(i.first, i.last))
Base.string(i::IntervalValue{IPv4, T}) where T = string(IPRange{IPv4}(i.first, i.last))
