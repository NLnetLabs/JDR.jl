module ASN

export Node, Leaf, print_node, append!, isleaf, parent

abstract type AbstractNode end
mutable struct Node <: AbstractNode
    parent::Union{Nothing, AbstractNode}
    children::Union{Nothing, Array{Node}}
    tag::Any #FIXME make this a DER.AbstractTag and benchmark
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

Leaf(t::T) where {T <: Any } = Node(nothing, nothing, t)
#Node(t::T) where {T <: Any } = Node(nothing, Vector{Node}(undef, 1), t)
#Node(t::T) where {T <: Any } = Node(nothing, [], t)
Node(t::T) where {T <: Any } = Node(nothing, [], t)


function Base.show(io::IO, n::Node)
    if !isnothing(n.tag)
        print(io, n.tag)
    else
        print(io, "__")
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


####################
# validation helpers
####################
# TODO move Tag{} to ASN.jl
# that way, we can use the type here
# and it is also more correct (the Tags are ASN, not DER)
function contains(t::Node, s::String)
    found = false
    while !found
        
    end
end


end # module
