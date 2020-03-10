module ASN

export Node, Leaf, print_node, append!, isleaf, parent

abstract type AbstractNode end
mutable struct Node <: AbstractNode
    parent::Union{Nothing, AbstractNode}
    children::Union{Nothing, Array{Node}}
    tag::Any
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
Node(t::T) where {T <: Any } = Node(nothing, Vector(undef, 1), t)


function Base.show(io::IO, n::Node)
    if !isnothing(n.tag)
        print(io, n.tag)
    else
        print(io, "__")
    end
end


function print_node(n::Node; traverse::Bool=false, level::Integer=0)
    #println(level, n)
    println(n)
    if traverse && !isnothing(n.children)
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



end # module
