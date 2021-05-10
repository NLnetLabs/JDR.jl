module ASN

using JDR.Common: IPRange, Remark, RemarkCounts, RemarkCounts_t, remark_ASN1Issue!, oid_to_str

using Dates: DateTime, Year, year, @dateformat_str
using Sockets: IPv6, IPv4

export Tag, Tagnumber, InvalidTag, Node, istag, iscontextspecific, value, constructed, print_node
# from validation_common:
export check_tag, check_OID, check_value, childcount, check_contextspecific, check_extensions, check_attribute
export get_extensions, to_bigint, bitstring_to_v6range, bitstrings_to_v6range, bitstring_to_v4range, bitstrings_to_v4range


@enum Tagnumber begin
RESERVED_ENC
BOOLEAN
INTEGER
BITSTRING
OCTETSTRING
NULL
OID
ODESC
ETYPE
REAL
ENUM
EMBEDDEDPDV
UTF8STRING
ROID
TIME
RESERVED_FUTURE
SEQUENCE
SET
NUMERICSTRING
PRINTABLESTRING
T61STRING
VIDEOTEXSTRING
IA5STRING
UTCTIME
GENTIME
Unimplemented = 998
InvalidTag = 999
end


export RESERVED_ENC,
    BOOLEAN,
    INTEGER,
    BITSTRING,
    OCTETSTRING,
    NULL,
    OID,
    ODESC,
    ETYPE,
    REAL,
    ENUM,
    EMBEDDEDPDV,
    UTF8STRING,
    ROID,
    TIME,
    RESERVED_FUTURE,
    SEQUENCE,
    SET,
    NUMERICSTRING,
    PRINTABLESTRING,
    T61STRING,
    VIDEOTEXSTRING,
    IA5STRING,
    UTCTIME,
    GENTIME,
    Unimplemented,
    InvalidTag

# FIXME macro/eval this export
#for t in instances(Tagnumber)
#    #@eval :( export Symbol($t) )
#    eval(export Symbol($t))
#end

struct Tag
    class_constructed::UInt8
    number::Tagnumber
    len::Int32
    len_indef::Bool
    headerlen::Int8
    value::Union{Nothing, Vector{UInt8}}
    offset_in_file::Integer
end

import Base.convert
convert(::Type{Tagnumber}, i::UInt8) = Tagnumber(Int(i))

istag(t::Tag, tn::Tagnumber) = t.number == tn
class(t::Tag) = t.class_constructed >> 6 # bit 8-7
constructed(t::Tag) = t.class_constructed & 0x20 == 0x20 # bit 6
iscontextspecific(t::Tag) = class(t) == 0x02


function value(t::Tag; force_reinterpret=false)
    if istag(t, BOOLEAN)
        # FIXME DER has stricter constraints for TRUE
        # all bits should be 1 for true
        t.value[1] != 0  
    elseif istag(t, INTEGER)
        if t.len <= 8
            reinterpret(Int64, resize!(reverse(t.value), 8))[1]
        else
            parse(BigInt, bytes2hex(t.value), base=16)
        end


        #if t.len > 5 && !force_reinterpret
        #    "$(t.len * 8)bit integer" #FIXME not accurate, perhaps the lenbytes itself cause that
        #elseif t.len <= 8
        #    reinterpret(Int64, resize!(reverse(t.value), 8))[1]
        #else
        #    parse(BigInt, bytes2hex(t.value), base=16)
        #end
    elseif istag(t, PRINTABLESTRING) || istag(t, IA5STRING) || istag(t, UTF8STRING)
        String(copy(t.value))

    elseif istag(t, GENTIME)
        DateTime(String(copy(t.value)), dateformat"yyyymmddHHMMSSZ")
    elseif istag(t, UTCTIME)
        ts = DateTime(String(copy(t.value)), dateformat"yymmddHHMMSSZ")
        if year(ts) < 50
            ts += Year(2000)
        else
            ts += Year(1900)
        end
        ts
    elseif istag(t, BITSTRING)
        if t.len > 10
            "*blob*"
        elseif t.len >= 2
            bitstring(t.value[2] >> t.value[1])
        else
            "*empty*"
        end
    else
        @warn "value for unimplemented type ", t.number
    end
end

function Base.show(io::IO, t::Tag)
    if !iscontextspecific(t)
        print(io, t.number)
    else
        print(io, '[', Int(t.number), ']')
    end
    print(io, " (", t.len, ')' )
end

##
## TMP commented out, first get DER.parse_recursive working
##
#=
function Base.show(io::IO, t::Tag{T}) where {T<:AbstractTag}
    print(io, "[$(bitstring(t.class)[7:8])] ")
    len = if t.len == 0x80
        len = "indef."
    else
        t.len
    end
    print(io, "$(nameof(T)): $(value(t)) ($(len))")
end
function Base.show(io::IO, ::MIME"text/plain", ts::Array{Tag{T},1}) where {T<:AbstractTag}
    error("oh so now this show() is triggered?")
    for t in ts
        print(io, "___[$(bitstring(t.class)[7:8])] ")
        print(io, "$(nameof(T)): $(value(t)) ($(t.len))")
        print(io, "\n")
    end
end
Base.show(io::IO, t::Tag{CONTEXT_SPECIFIC})     = print(io, "CONTEXT-SPECIFIC [$(t.number)]")
Base.show(io::IO, t::Tag{Unimplemented})    = print(io, "Unimplemented tag $(t.number) ($(t.len))")
Base.show(io::IO, t::Tag{NULL}) where {T}   = print(io, "NULL")
function Base.show(io::IO, t::Tag{BITSTRING})
    print(io, "BITSTRING: ")
    if t.constructed
        print(io, "(constr.) ")
    else
        print(io, "(prim.) $(value(t))")
    end
    print(io, " ($(t.len))")
end
value(t::Tag{T}) where {T} = "**RAW**: $(t.value)"

value(t::Tag{RESERVED_ENC}) = ""
value(t::Tag{SEQUENCE}) = ""
value(t::Tag{SET}) = ""
# FIXME DER is stricter for BOOLEANs than this
# all bits should be 1 for true
value(t::Tag{BOOLEAN}) = t.value[1] != 0 
value(t::Tag{PRINTABLESTRING}) = String(copy(t.value))

#value(t::Tag{UTCTIME}) = String(copy(t.value))
#value(t::Tag{GENTIME}) = String(copy(t.value))
value(t::Tag{GENTIME}) = DateTime(String(copy(t.value)), dateformat"yyyymmddHHMMSSZ")
function value(t::Tag{UTCTIME}) 
    ts = DateTime(String(copy(t.value)), dateformat"yymmddHHMMSSZ")
    if year(ts) < 50
        ts += Year(2000)
    else
        ts += Year(1900)
    end
    ts
end


value(t::Tag{UTF8STRING}) = String(copy(t.value))
value(t::Tag{IA5STRING}) = String(copy(t.value))
function value(t::Tag{INTEGER}; force_reinterpret=false) where {T}
    if t.len > 5 && !force_reinterpret
        "$(t.len * 8)bit integer" #FIXME not accurate, perhaps the lenbytes itself cause that
    elseif t.len <= 8
        reinterpret(Int64, resize!(reverse(t.value), 8))[1]
    else
        parse(BigInt, bytes2hex(t.value), base=16)
    end
end

function value(t::Tag{BITSTRING}) where {T} 
    if t.len > 10
        "*blob*"
    elseif t.len >= 2
        bitstring(t.value[2] >> t.value[1])
    else
        "*empty*"
    end
end

function value(t::Tag{OCTETSTRING}) where {T} 
    if t.constructed 
        return nothing
    elseif t.len <= 8
        return t.value
    end
    return "*blob*"
end


function value(t::Tag{OID}) 
    if t.class == 0x02 # context specific TODO find documentation for this
        return String(copy(t.value))
    end

    buf = IOBuffer(t.value) 
    subids = Array{Int32,1}([0]) # 
    while !eof(buf)
        subid = 0
        byte = read(buf, 1)[1]
        while byte & 0x80 == 0x80 # first bit is 1
            subid = (subid << 7) | (byte & 0x7f) # take the last 7 bits
            byte = read(buf, 1)[1]
        end
        subid = (subid << 7) | (byte & 0x7f) # take the last 7 bits
        push!(subids, subid) #reinterpret(Int32, resize!(reverse(subid), 4)))
    end
    # get the first two sub identifiers:
    if subids[2] >= 120
        subids[1] = 3
        subids[2] %= 120
    elseif subids[2] >= 80
        subids[1] = 2
        subids[2] %= 80
    elseif subids[2] >= 40
        subids[1] = 1
        subids[2] %= 40
    else
        # is this possible?
        # x=0, y = subid[2] 
        # so actually we do not need to do anything
    end

    join(subids, ".")
end
=#

mutable struct Node
    #parent::Union{Nothing, Node}
    children:: Union{Nothing, Vector{Node}}
    tag::Tag #FIXME make this a DER.AbstractTag and benchmark
    validated::Bool
	remarks::Union{Nothing, Vector{Remark}}
    nicename::Union{Nothing, String}
    nicevalue::Union{Nothing, String}
    buf::Union{Nothing, IOBuffer}
end

function append!(p::Node, c::Node) :: Node
    if isnothing(p.children)
        p.children = [c]
    else
        push!(p.children, c)
    end
    #c.parent = p
    p
end

import JDR.Common: count_remarks # import so we can extend it
function count_remarks(tree::Node) :: RemarkCounts_t
    cnts = RemarkCounts()
    for n in iter(tree)
        if !isnothing(n.remarks)
            for r in n.remarks
                cnts[r.lvl] = get(cnts, r.lvl, 0) + 1
            end
        end
    end
    cnts
end

Node(t::Tag) = Node(nothing, t, false, nothing, nothing, nothing, nothing)

function child(node::Node, indices...) :: Node
    current = node
    for i in indices
        try
        current = current.children[i]
        catch e
            #@warn "invalid child $(i) in $(indices), $(stacktrace()[4])"
            throw("invalid child $(i) in $(indices), $(stacktrace()[4])")
        end
    end
    current
end

Base.getindex(node::Node, indices...) = child(node, indices...)

function Base.show(io::IO, n::Node)
    if !isnothing(n.tag)
        if !isnothing(n.nicename) printstyled(io, n.nicename, ' ', color=:cyan) end
        if n.validated
            printstyled(io, n.tag, color=:green)
        else
            print(io, n.tag)
        end
        if !isnothing(n.nicevalue)
            printstyled(io, ' ', n.nicevalue; color=:magenta)
        end
        if !isnothing(n.remarks) && !isempty(n.remarks)
            printstyled(io, " [$(length(n.remarks))] "; color=:red)
            for (idx, r) in enumerate(n.remarks)
                printstyled(io, idx, ": "; color=:red)
                printstyled(io, n.remarks[idx], " "; color=:yellow)
            end
        end
    else
        print(io, "__EMPTY NODE__")
    end
end

mutable struct PrintState
    traverse::Bool
    indent::Integer
    max_lines::Integer
    printed_lines::Integer
end
PrintState() = PrintState(false, 0, 0, 0)
inc(p::PrintState) = p.printed_lines += 1
done(p::PrintState) = p.max_lines > 0 && p.printed_lines == p.max_lines


function print_node(n::Node, ps::PrintState)
    if done(ps)
        return
    end
    if ps.traverse
        inc(ps)
        println(n)
        ps.indent += 1
        if !isnothing(n.children)
            for (i, c) in enumerate(n.children)
                print(repeat("  ", ps.indent))
                print_node(c, ps)
            end
        end
        ps.indent -= 1
    end
end
function print_node(n::Node; traverse::Bool=true, max_lines::Integer=0)  
    print_node(n, PrintState(traverse, 0, max_lines, 0))
    if max_lines > 0
        printstyled("\r---- max-lines was $(max_lines) ----\n", color=:red)
    end
end

# used in count_remarks
function iter(tree::Node, res::Vector{Node}=Vector{Node}([])) :: Vector{Node}
    Base.push!(res, tree)
    if !isnothing(tree.children)
        for c in tree.children
            iter(c, res)
        end
    end
    res
end

#function tagtype(n::Node) :: DataType
#    typeof(n.tag).parameters[1]
#end
#function tagtype(t::Tag{<:AbstractTag}) :: DataType
#    typeof(t).parameters[1]
#end



####################
# validation helpers
####################
# TODO are these used?

#=
function iter(tree::Node, res::Vector{Node}=Vector{Node}([])) :: Vector{Node}
    Base.push!(res, tree)
    if !isnothing(tree.children)
        for c in tree.children
            iter(c, res)
        end
    end
    res
end

lazy_iter(tree::Node) = Channel(ctype=Node) do c
    put!(c, tree)
        if !isnothing(tree.children)
            for child in tree.children
                lazy_iter(child, c)
            end
        end
end
function contains(tree::Node, tagtype::Type{T}, v::Any) where {T<:AbstractTag}
    found = false
    for node in iter(tree)
        if node.tag isa Tag{tagtype} && value(node.tag) == v
            found = true
            break
        end
    end
    found
end

# Set of Pairs (tagtype, value)
function contains_set(tree::Node, tags::Set{Pair{Type{T} where {T<:AbstractTag}, Any}})
    for node in iter(tree)
        for (tagtype, v) in tags
            if (node.tag isa Tag{tagtype} && tagtype == ASN.OID)
                if node.tag.value == v
                    delete!(tags, tagtype => v)
                    break
                end
            elseif (node.tag isa Tag{tagtype} && value(node.tag) == v)
                delete!(tags, tagtype => v)
                break
            end
        end
    end
    isempty(tags)
end

function contains_in_order(tree::Node, tags::Vector{Pair{Type{T} where {T<:AbstractTag}, Any}})
    for node in iter(tree)#,
        (tagtype, v) = first(tags)
        if ((node.tag isa Tag{tagtype} == Tag{ASN.OID} && node.tag.value == v)
            || (node.tag isa Tag{tagtype} && value(node.tag) == v))
            popfirst!(tags)
            if isempty(tags) break end
        end
    end
    isempty(tags)
end


lazy_iter(tree::Node, chan::Channel{Node}) = begin
    put!(chan, tree)
    if !isnothing(tree.children)
        for child in tree.children
            lazy_iter(child, chan)
        end
    end
end


function lazy_contains(tree::Node, tagtype::Type{T}, v::Any) where {T<:AbstractTag}
    found = false
    for node in lazy_iter(tree)
        if node.tag isa Tag{tagtype} && value(node.tag) == v
            found = true
            break
        end
    end
    found
end

=#

include("validation_common.jl")

end # module
