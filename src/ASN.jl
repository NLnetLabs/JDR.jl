module ASN

export Tag, AbstractTag, Node, AbstractNode, Leaf
export print_node, append!, isleaf, parent, iter, lazy_iter

export Unimplemented, InvalidTag, SEQUENCE, SET, RESERVED_ENC, OCTETSTRING, BITSTRING

abstract type AbstractTag end 
struct Tag{T}
    class::UInt8
    constructed::Bool # PC bit
    number::UInt8
    len::Int32
    len_indef::Bool
    value::Union{Nothing, Array{UInt8, 1}}
end

struct  Unimplemented   <:	AbstractTag	end
struct  InvalidTag      <:	AbstractTag	end
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
struct  CHAR            <:  AbstractTag end
struct  PRINTABLESTRING <:  AbstractTag end
struct  IA5STRING       <:  AbstractTag end

struct  UTCTIME         <:  AbstractTag end
struct  GENTIME         <:  AbstractTag end


Tag(class, constructed, number, len, len_indef, value) :: Tag{<: AbstractTag} = begin
    t = if number   == 0    Tag{RESERVED_ENC} 
    elseif number   == 1    Tag{BOOLEAN}
    elseif number   == 2    Tag{INTEGER}
    elseif number   == 3    Tag{BITSTRING}
    elseif number   == 4    Tag{OCTETSTRING}
    elseif number   == 5    Tag{NULL}
    elseif number   == 6    Tag{OID}
    elseif number   == 12   Tag{UTF8STRING}
    elseif number   == 16   Tag{SEQUENCE}
    elseif number   == 17   Tag{SET}
    elseif number   == 22   Tag{IA5STRING}
    elseif number   == 23   Tag{UTCTIME}
    elseif number   == 24   Tag{GENTIME}
    #elseif number   in (18:22)   Tag{CHAR}
    elseif number   == 19   Tag{PRINTABLESTRING}
    elseif number   in (25:30)   Tag{CHAR}
    else                    Tag{Unimplemented}
    end
    t(class, constructed, number, len, len_indef, value)
end

#InvalidTag() = Tag{InvalidTag}(0, 0, 0, 0, [])
Tag{InvalidTag}() = Tag{InvalidTag}(0, 0, 0, 0, false, [])


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
Base.show(io::IO, t::Tag{Unimplemented}) = print(io, "Unimplemented tag $(t.number) ($(t.len))")
Base.show(io::IO, t::Tag{NULL}) where {T} = print(io, "NULL")
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
function value(t::Tag{INTEGER}) where {T}
    if t.len > 5
        "$(t.len * 8)bit integer" #FIXME not accurate, perhaps the lenbytes itself cause that
    else
        reinterpret(Int64, resize!(reverse(t.value), 8))
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
        @warn "constructed OCTETSTRING, not allowed in DER"
        #error("constructed OCTETSTRING, not allowed in DER")
        return nothing
    end

    if t.len <= 4 #TODO this is... horrible?
        # all octetstrings must be primitive (in DER), so how do we know whether we should look for
        # another (leaf) tag inside of this octetstring? for now, check the length..
        #@debug "horrible return"
        return t.value
    end

    return ""
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
    parent::Union{Nothing, AbstractNode}
    children::Union{Nothing, Array{Node}}
    tag::Any #FIXME make this a DER.AbstractTag and benchmark
    remarks::Union{Nothing, Vector{String}}
end


isleaf(n::Node) :: Bool = isnothing(n.children)
function parent(n::Node) :: Node 
    n.parent
end

function append!(p::Node, c::Node) :: Node
    push!(p.children, c)
    c.parent = p
    p
end

#Leaf(t::T) where {T <: Any } = Node(nothing, nothing, t, nothing)
#Node(t::T) where {T <: Any } = Node(nothing, Vector{Node}(undef, 1), t)
#Node(t::T) where {T <: Any } = Node(nothing, [], t)
Node(t::T) where {T <: Any } = Node(nothing, [], t, nothing)


function Base.show(io::IO, n::Node)
    if !isnothing(n.tag)
        print(io, n.tag)
        if !isnothing(n.remarks) && !isempty(n.remarks)
            printstyled(io, " [$(length(n.remarks))] "; color=:red)
            printstyled(io, n.remarks[1]; color=:yellow)
        end
    else
        print(io, "__EMPTY NODE__")
    end
end


function print_node(n::Node; traverse::Bool=false, level::Integer=0)
    #println(n)
    if traverse && !isnothing(n.children)
        println(level, n) #FIXME is there an extra node at the end at level 0?
        level += 1
        for (i, c) in enumerate(n.children)
            print(repeat("  ", level))
            print_node(c; traverse=true, level=level)
            #println(c.tag)
        end
        level -= 1
    end
    #if level == 1 
    #    #println()
    #end
end


######################
# RPKI Objects / files
######################


# moved to src/RPKI.jl


####################
# validation helpers
####################

function iter(tree::Node) 
    result = [tree]
    if !isnothing(tree.children)
        for (i, c) in enumerate(tree.children)
            Base.append!(result, iter(c))
        end
    end
    #@debug "result of size $(length(result))"
    result
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
            if node.tag isa Tag{tagtype} && value(node.tag) == v
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
        if node.tag isa Tag{tagtype} && value(node.tag) == v
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


end # module
