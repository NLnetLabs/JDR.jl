module JSONHelpers
using JSON2
using IPNets
using HTTP
using Dates
using ..RPKI
using ..JDR.Common
using ..ASN

export to_root, to_vue_branch, to_vue_tree, length


JSON2.@format RPKI.RPKINode begin
        parent => (;exclude=true,)
end

JSON2.@format RPKI.RPKIObject{T} where T begin
        tree => (;exclude=true,)
end

# custom view for RPKIObject{T}
# includes the tree, but does not link to parent or children
# howto: https://github.com/quinnj/JSON2.jl/issues/12
struct ObjectDetails{T}
    filename::String
    tree::RPKI.Node
    object::T
    objecttype::String
    remarks::Union{Nothing, Vector{RPKI.Remark}}
    remark_counts_me::Union{Nothing, RemarkCounts_t}
end

function ObjectDetails(r::RPKI.RPKIObject, rc::RemarkCounts_t) 
    # we parse this again, because it is removed from the main tree/lookup 
    tmp = RPKI.RPKIObject(r.filename)
    RPKI.check(tmp)
    
    d = ObjectDetails(r.filename,
                      tmp.tree,
                      r.object,
                      string(nameof(typeof(r.object))),
                      r.remarks,
                      rc # FIXME assert r.remarks ==~ rc
                    )
    return d
end

struct ObjectSlim{T}
    filename::String
    details_url::String # this is only for ease of development
    object::T # FIXME force this to be a SlimCER or SlimMFT etc
    objecttype::String
    remarks::Union{Nothing, Vector{RPKI.Remark}}
    remark_counts_me::RemarkCounts_t
end

const DOMAIN = "http://localhost:8081/" # TODO move this into separate config

details_url(filename::String) = DOMAIN * "api/v1/object/" * HTTP.escapeuri(filename)
function ObjectSlim(r::RPKI.RPKIObject, rc::RemarkCounts_t) 
    ObjectSlim(r.filename,
               details_url(r.filename),
               to_slim(r.object),
               string(nameof(typeof(r.object))),
               r.remarks,
               rc # FIXME assert r.remarks ==~ rc
            )
end


struct Basename
    filename::String
end
JSON2.@format ObjectDetails begin
    filename => (; jsontype=Basename,)
end
JSON2.write(io::IO, bn::Basename) = JSON2.write(io, basename(bn.filename))
Base.convert(Basename, s) = Basename(s)

function JSON2.write(io::IO, t::ASN.Tag{T}) where {T}
    JSON2.write(io, "$(nameof(ASN.tagtype(t))) ($(t.len))")
    #JSON2.write(io, " ($(t.len))")
end


JSON2.write(io::IO, p::IPNet) = JSON2.write(io, string(p.netaddr)*'/'*string(p.netmask))


# Slim copy of RPKI.CER, with empty prefixes and ASNs Vectors
struct SlimCER 
    pubpoint::String
    manifest::String
    rrdp_notify::String
    inherit_prefixes::Bool
    prefixes::Vector{Union{IPNet, Tuple{IPNet, IPNet}}}
    inherit_ASNs::Bool
    ASNs::Vector{Union{Tuple{UInt32, UInt32}, UInt32}}
end
SlimCER(cer::RPKI.CER) = SlimCER(cer.pubpoint, cer.manifest, cer.rrdp_notify, cer.inherit_prefixes, [], cer.inherit_ASNs, [])
JSON2.@format SlimCER begin
    prefixes => (;exclude=true,)
    ASNs => (;exclude=true,)
end

# Slim copy of RPKI.MFT, with an empty files Vector
struct SlimMFT
    files::Vector{String}
    loops::Union{Nothing, Vector{String}}
    missing_files::Union{Nothing, Vector{String}}
    this_update::Union{Nothing, DateTime}
    next_update::Union{Nothing, DateTime}
end
SlimMFT(mft::RPKI.MFT) = SlimMFT([], mft.loops, mft.missing_files, mft.this_update, mft.next_update)
JSON2.@format SlimMFT begin
    files => (;exclude=true,)
end


to_slim(o::RPKI.MFT) = SlimMFT(o)
to_slim(o::RPKI.CER) = SlimCER(o)
to_slim(o::RPKI.ROA) = o


# to_root is used to show a part of the tree, namely from the passed object up
# to the root. The circular ref between  `parent` and `children` in the RPKINode
# struct causes trouble in the JSON generation, so to_root returns a simple
# Vector with ObjectSlim's, and no explicition pointers to parents or children.
function to_root(node::RPKI.RPKINode) :: Vector{ObjectSlim}
    current = node
    res = Vector{ObjectSlim}([ObjectSlim(current.obj, current.remark_counts_me)])
    while !isnothing(current.parent)
        if !isnothing(current.parent.obj)
            push!(res, ObjectSlim(current.parent.obj, current.parent.remark_counts_me))
        end
        current = current.parent
    end
    res
end

mutable struct VueNode
    children::Vector{VueNode}
    mates::Vector{VueNode}
    name::String
    object::Union{Nothing, ObjectSlim}
end

function to_vue_branch(node::RPKI.RPKINode)
    nodes = reverse(to_root(node))
    root = VueNode([], [], "root", nothing)
    current = root
    for n in nodes
        if n.objecttype == "MFT"
            #@debug "MFT!"
            current.mates = [VueNode([], [], basename(n.filename), n)]
            #current = current.children[1]
        else
            current.children = [VueNode([], [], basename(n.filename), n)]
            current = current.children[1]
        end
        #@debug "current:", current
    end
    root
end

import Base.length
function length(vue_branch::VueNode)
    res = 0
    v = vue_branch
    while !isempty(v.children)
        res += 1
        v = v.children[1]
    end
    res
end

function to_vue_tree(branches::Vector)
    
    for b in branches
        @debug "branch length:", length(b)
    end
    sort!(branches, by = x -> length(x), rev=true)
    @debug "----"
    for b in branches
        @debug "branch length:", length(b)
    end
    
    left = branches[1]
    for b in (2:length(branches)) 
        right = branches[b]

        l = left
        r = right

        done = false
        while ! done
            @debug "children in left:", length(l.children)
            if isnothing(findfirst(x -> x.object.filename == r.children[1].object.filename, l.children))
                @debug "different", r.children[1].object.filename
                push!(l.children, r.children[1])
                done = true
                continue
            else
                @debug "left_child same as r.children[1]!, breaking.."
            end
            l = l.children[1]
            r = r.children[1]
        end
    end
    left
end



end # module
