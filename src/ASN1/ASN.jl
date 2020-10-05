module ASN
using ...JDR.Common

export Tag, AbstractTag, Node, AbstractNode, Leaf
export value, print_node, append!, isleaf, iter, lazy_iter #parent
export remark!, child, getindex, tagtype
export @oid

export  Unimplemented, InvalidTag, SEQUENCE, SET, RESERVED_ENC, OCTETSTRING,
        BITSTRING, PRINTABLESTRING, CONTEXT_SPECIFIC


abstract type AbstractTag end 
struct  Unimplemented   <:	AbstractTag	end
struct  InvalidTag      <:	AbstractTag	end

struct CONTEXT_SPECIFIC <:  AbstractTag end

struct	RESERVED_ENC   	<:	AbstractTag	end
struct	BOOLEAN        	<:	AbstractTag	end
struct	INTEGER        	<:	AbstractTag	end
struct	BITSTRING      	<:	AbstractTag	end
struct	OCTETSTRING    	<:	AbstractTag	end
struct	NULL           	<:	AbstractTag	end
struct	OID            	<:	AbstractTag	end
struct	ODESC          	<:	AbstractTag	end
struct	ETYPE          	<:	AbstractTag	end
struct	REAL           	<:	AbstractTag	end
struct	ENUM           	<:	AbstractTag	end
struct	EMBEDDEDPDV    	<:	AbstractTag	end
struct	UTF8STRING     	<:	AbstractTag	end
struct	ROID           	<:	AbstractTag	end
struct	TIME           	<:	AbstractTag	end
struct	RESERVED_FUTURE	<:	AbstractTag	end
struct	SEQUENCE       	<:	AbstractTag	end
struct	SET            	<:	AbstractTag	end
#struct  CHAR            <:  AbstractTag end
struct  PRINTABLESTRING <:  AbstractTag end
struct  IA5STRING       <:  AbstractTag end

struct  UTCTIME         <:  AbstractTag end
struct  GENTIME         <:  AbstractTag end

struct Tag{AbstractTag}
    class::UInt8
    constructed::Bool # PC bit
    number::Integer
    len::Int32
    len_indef::Bool
    value::Union{Nothing, Array{UInt8, 1}}
    offset_in_file::Integer
end


Tag(class::UInt8, constructed::Bool, number::Integer, len::Int32, len_indef::Bool, value, offset_in_file::Integer) = begin
    if class == 0x02 # Context-specific
        Tag{CONTEXT_SPECIFIC}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(0)    
        Tag{RESERVED_ENC}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(1)
        Tag{BOOLEAN}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(2)
        Tag{INTEGER}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(3)
        Tag{BITSTRING}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(4)  
        Tag{OCTETSTRING}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(5)  
        Tag{NULL}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(6)  
        Tag{OID}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(12) 
        Tag{UTF8STRING}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(16) 
        Tag{SEQUENCE}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(17) 
        Tag{SET}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(22) 
        Tag{IA5STRING}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(23) 
        Tag{UTCTIME}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt8(24) 
        Tag{GENTIME}(class, constructed, number, len, len_indef, value, offset_in_file)
    elseif number   == UInt(19)  
        Tag{PRINTABLESTRING}(class, constructed, number, len, len_indef, value, offset_in_file)
    else
        Tag{Unimplemented}(class, constructed, number, len, len_indef, value, offset_in_file)
    end 
end

Tag{InvalidTag}() = Tag{InvalidTag}(0, 0, 0, 0, false, [], 0)


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
value(t::Tag{UTCTIME}) = String(copy(t.value))
value(t::Tag{GENTIME}) = String(copy(t.value))
value(t::Tag{UTF8STRING}) = String(copy(t.value))
value(t::Tag{IA5STRING}) = String(copy(t.value))
function value(t::Tag{INTEGER}; force_reinterpret=false) where {T}
    if t.len > 5 && !force_reinterpret
        "$(t.len * 8)bit integer" #FIXME not accurate, perhaps the lenbytes itself cause that
    else
        reinterpret(Int64, resize!(reverse(t.value), 8))[1]
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

abstract type AbstractNode end
mutable struct Node <: AbstractNode
    #parent::Union{Nothing, Node}
    children:: Union{Nothing, Vector{Node}}
    tag #FIXME make this a DER.AbstractTag and benchmark
    validated::Bool
	remarks::Union{Nothing, Vector{Remark}}
    nicename::Union{Nothing, String}
end

isleaf(n::Node) :: Bool = isnothing(n.children)

#function parent(n::Node) :: Node 
#    n.parent
#end

function append!(p::Node, c::Node) :: Node
    if isnothing(p.children)
        p.children = [c]
    else
        push!(p.children, c)
    end
    #c.parent = p
    p
end

import JDR.Common.count_remarks # import so we can extend it
function count_remarks(tree::Node) :: RemarkCounts_t
    cnts = RemarkCounts()
    for n in iter(tree)
        if !isnothing(n.remarks)
            for r in n.remarks
                cnts[r.lvl] += 1
            end
        end
    end
    cnts
end

#Node(t::T) where {T <: Any } = Node(nothing, nothing, t, false, nothing)
Node(t::T) where {T <: Any } = Node(nothing, t, false, nothing, nothing)

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
        if !isnothing(n.nicename) printstyled(io, n.nicename, color=:cyan) end
        if n.validated
            printstyled(io, n.tag, color=:green)
        else
            print(io, n.tag)
        end
        if !isnothing(n.remarks) && !isempty(n.remarks)
            printstyled(io, " [$(length(n.remarks))] "; color=:red)
            printstyled(io, n.remarks[end]; color=:yellow)
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

function tagtype(n::Node) :: DataType
    typeof(n.tag).parameters[1]
end
function tagtype(t::Tag{<:AbstractTag}) :: DataType
    typeof(t).parameters[1]
end


function _html(tree::Node, io::IOStream)

    write(io, "<li class='asnnode $(tree.validated ? "validated" : "")'>")
    write(io, "<span class='$(! isnothing(tree.remarks) ? "remark" : "")'>")
    write(io, "$(nameof(typeof(tree.tag).parameters[1])): $(value(tree.tag))") # ($(tree.tag.len))")
    if ! isnothing(tree.remarks)
        write(io, "<div class='remarks-container'>")
        for r in tree.remarks
            write(io, "$(r) <br/>")
        end
        write(io, "</div>")
    end
    write(io, "</span>\n")

    # children?
    if !isnothing(tree.children)
        write(io, "<ul class='asn'>\n")
        for c in tree.children
            _html(c, io)
        end
        write(io, "</ul>\n")
    end
    write(io, "</li>\n")

end

function html(tree::Node, output_fn::String) 
    STATIC_DIR = normpath(joinpath(pathof(parentmodule(ASN)), "..", "..", "static"))
    open(output_fn, "w") do io
        write(io, "<link rel='stylesheet' href='file://$(STATIC_DIR)/style.css'/>\n")
        write(io, "<h1>JDR</h1>\n\n")
        write(io, "<ul id='main' class='asn'>\n")
        #write(io, "<li>root</li>\n")
        for c in tree.children
            _html(c, io)
        end
        write(io, "</ul>\n")
        write(io, "<!-- done -->\n")
        write(io, "<script type='text/javascript' src='file://$(STATIC_DIR)/javascript.js'></script>")
    end
    @debug "written $(output_fn)"
end


####################
# validation helpers
####################

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


include("validation_common.jl")

end # module