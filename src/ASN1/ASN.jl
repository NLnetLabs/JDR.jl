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
Invalid = 999
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
    Invalid

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
convert(::Type{Tagnumber}, i::Int) = Tagnumber(Int(i))

istag(t::Tag, tn::Tagnumber) = t.number == tn
class(t::Tag) = t.class_constructed >> 6 # bit 8-7
constructed(t::Tag) = t.class_constructed & 0x20 == 0x20 # bit 6
iscontextspecific(t::Tag) = class(t) == 0x02

InvalidTag() = Tag(0, Invalid, 0, false, 0, nothing, 0)


function value(t::Tag; force_reinterpret=false)
    if istag(t, BOOLEAN)
        # FIXME DER has stricter constraints for TRUE
        # all bits should be 1 for true
        if t.value[1] != 0 
            if t.value[1] != 0xff
                @warn "DER encoded boolean must be 0xff for TRUE"
            end
            return true
        end
        return false
    elseif istag(t, INTEGER)
        if t.len <= 8
            reinterpret(Int64, resize!(reverse(t.value), 8))[1]
        else
            parse(BigInt, bytes2hex(t.value), base=16)
        end
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

mutable struct Node
    children:: Union{Nothing, Vector{Node}}
    tag::Tag
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
        if i > length(current.children)
            @error "trying to access non-existing ASN1 node"
            break
        end
        current = current.children[i]
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

####################
# validation helpers
####################

include("validation_common.jl")

end # module
