module JSONHelpers
using JSON2
using IPNets
using HTTP
using Dates
using ..RPKI
using ..JDR.Common
using ..JDR.RPKICommon
using ..ASN1

export ObjectDetails, to_root, to_vue_branch, to_vue_tree, to_vue_pubpoints, length, get_vue_leaf_node


JSON2.@format RPKI.RPKINode begin
        parent => (;exclude=true,)
end

JSON2.@format RPKI.RPKIObject{T} where T begin
        tree => (;exclude=true,)
end

JSON2.@format RPKI.ROA begin
        prefixes_v6_intervaltree => (;exclude=true,)
        prefixes_v4_intervaltree => (;exclude=true,)
end
JSON2.@format RPKI.CER begin
        prefixes_v6_intervaltree => (;exclude=true,)
        prefixes_v4_intervaltree => (;exclude=true,)
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
    remarks_tree::Union{Nothing, Vector{RPKI.Remark}}
    sig_valid::Union{Nothing, Bool}
end

function ObjectDetails(r::RPKI.RPKIObject, rc::RemarkCounts_t) 
    # we parse this again, because it is removed from the main tree/lookup 
    tmp = RPKI.RPKIObject(r.filename)
    RPKI.check_ASN1(tmp, RPKI.TmpParseInfo(;nicenames=true))
    @assert isnothing(tmp.remarks_tree)
    RPKI.collect_remarks_from_asn1!(tmp, tmp.tree)
    
    d = ObjectDetails(r.filename,
                      tmp.tree,
                      r.object,
                      string(nameof(typeof(r.object))),
                      r.remarks,
                      rc, # FIXME assert r.remarks ==~ rc
                      tmp.remarks_tree,
                      r.sig_valid
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
    remark_counts_children::RemarkCounts_t
end

const DOMAIN = "http://localhost:8081/" # TODO move this into separate config

details_url(filename::String) = DOMAIN * "api/v1/object/" * HTTP.escapeuri(filename)
function ObjectSlim(r::RPKI.RPKIObject, rcm::RemarkCounts_t, rcc::RemarkCounts_t) 
    ObjectSlim(r.filename,
               details_url(r.filename),
               to_slim(r.object),
               string(nameof(typeof(r.object))),
               r.remarks,
               rcm, # FIXME assert r.remarks ==~ rcm
               rcc
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

function JSON2.write(io::IO, t::ASN1.Tag{T}) where {T}
    JSON2.write(io, "$(nameof(ASN1.tagtype(t))) ($(t.len))")
    #JSON2.write(io, " ($(t.len))")
end


JSON2.write(io::IO, p::IPNet) = JSON2.write(io, string(p.netaddr)*'/'*string(p.netmask))


# Slim copy of RPKI.CER, with empty prefixes and ASNs Vectors
struct SlimCER 
    pubpoint::String
    manifest::String
    rrdp_notify::String

    inherit_v6_prefixes::Union{Nothing,Bool}
    inherit_v4_prefixes::Union{Nothing,Bool}

    #prefixes::Vector{Union{IPNet, Tuple{IPNet, IPNet}}}
    inherit_ASNs::Bool
    ASNs::Vector{Union{Tuple{UInt32, UInt32}, UInt32}}
end
SlimCER(cer::RPKI.CER) = begin
    SlimCER(cer.pubpoint, cer.manifest, cer.rrdp_notify,
                                 cer.inherit_v6_prefixes, cer.inherit_v4_prefixes,
                                 #[],
                                 cer.inherit_ASNs, [])
end
JSON2.@format SlimCER begin
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


struct SlimCRL
    revoked_serials::Vector{Integer}
end
SlimCRL(crl::RPKI.CRL) = SlimCRL(crl.revoked_serials)

to_slim(o::RPKI.MFT) = SlimMFT(o)
to_slim(o::RPKI.CER) = SlimCER(o)
to_slim(o::RPKI.CRL) = SlimCRL(o)
to_slim(o::RPKI.ROA) = o


# to_root is used to show a part of the tree, namely from the passed object up
# to the root. The circular ref between  `parent` and `children` in the RPKINode
# struct causes trouble in the JSON generation, so to_root returns a simple
# Vector with ObjectSlim's, and no explicition pointers to parents or children.
# now using RPKICommon.root_to
function to_root(node::RPKI.RPKINode) :: Vector{ObjectSlim}
    path = reverse(root_to(node)[2:end])
    @debug path[end]
    [ObjectSlim(n.obj, n.remark_counts_me, n.remark_counts_children) for n in path]
end


mutable struct VueNode
    children::Vector{VueNode}
    mates::Vector{VueNode}
    name::String
    object::Union{Nothing, ObjectSlim}
    newPubpoint::Union{Nothing,String}
end

JSON2.@format VueNode begin
    children => (omitempty=true,)
    mates => (omitempty=true,)
end


function get_vue_leaf_node(node::RPKI.RPKINode) ::RPKINode
    if node.obj.object isa CRL
        @assert length(node.siblings) == 1
        @assert node.siblings[1].obj.object isa CER
        @assert length(node.siblings[1].children) == 1
        @assert node.siblings[1].children[1].obj.object isa MFT
        node.siblings[1].children[1]
    elseif node.obj.object isa CER
        @assert length(node.children) == 1
        @assert node.children[1].obj.object isa MFT
        node.children[1]
    else
        node
    end
end

function to_vue_branch(node::RPKI.RPKINode)
    # make sure we 'end' on a ROA or CER:
    # MFT and CRLs are mates, in the vue tree terminology
    # MFT is a child of the CER in RPKINode terminology, CRL a sibling of the CER
    #
    # to get the 'full' last vue node, we need to go from the MFT back to the
    # root, because if we go from the CER, we miss the MFT (as the MFT is the
    # child of the CER)
    
    node = get_vue_leaf_node(node)

    nodes = root_to(node)[2:end] # start at 2 to skip the RPKINode root

    first_cer = VueNode([], [], basename(nodes[1].obj.filename), ObjectSlim(nodes[1].obj, nodes[1].remark_counts_me, nodes[1].remark_counts_children), nothing)
    root = VueNode([first_cer], [], "root", nothing, nothing)
    current = root
    current_pp = "root"
    for n in nodes
        siblings = [VueNode([], [], basename(s.obj.filename), ObjectSlim(s.obj, s.remark_counts_me, s.remark_counts_children), nothing) for s in n.siblings]
        vuenode = VueNode([], siblings, basename(n.obj.filename), ObjectSlim(n.obj, n.remark_counts_me, n.remark_counts_children), nothing)
        if n.obj.object isa CER 
            (this_pp, ) = split_scheme_uri(n.obj.object.pubpoint)
            if this_pp != current_pp
                vuenode.newPubpoint = this_pp
            end
            current_pp = this_pp
        end

        if n.obj.object isa MFT 
            push!(current.mates, vuenode)
        else
            current.children = [vuenode]
            current = current.children[1]
        end
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

function _pubpoints!(pp_tree::VueNode, tree::RPKI.RPKINode, current_pp::String)
    if isempty(tree.children)
        return
    end

    for c in tree.children
        if c.obj isa RPKI.RPKIObject{CER}
            this_pp = RPKI.split_scheme_uri(c.obj.object.pubpoint)[1]
            if this_pp != current_pp
                # check if this_pp exists on the same level
                if this_pp in [c2.name for c2 in pp_tree.children]
                    _pubpoints!(pp_tree, c, this_pp)
                else
                    #TODO check remark_counts_me, should we take the
                    #remarks_counts from the parent?
                    #but, pp_tree does not have any..
                    new_pp = VueNode([], [], this_pp, ObjectSlim(c.obj, c.remark_counts_me, c.remark_counts_children), nothing)
                    _pubpoints!(new_pp, c, this_pp)
                    push!(pp_tree.children, new_pp)
                end
            else
                _pubpoints!(pp_tree, c, current_pp)
            end
        elseif c.obj isa RPKI.RPKIObject{MFT}
            _pubpoints!(pp_tree, c, current_pp)
        else
            _pubpoints!(pp_tree, c, current_pp)
        end
    end
end

function to_vue_pubpoints(tree::RPKI.RPKINode)
    pp_tree = VueNode([], [], "root", nothing, nothing)
    for c in tree.children
        if ! isnothing(c.obj) && c.obj isa RPKI.RPKIObject{CER}
            pp = RPKI.split_scheme_uri(c.obj.object.pubpoint)[1]
            subtree = VueNode([], [], pp, ObjectSlim(c.obj, c.remark_counts_me, c.remark_counts_children), nothing)
            _pubpoints!(subtree, c, pp)
            push!(pp_tree.children, subtree)
        end
    end
    pp_tree
end

# TODO: use/move to Webservice unit test
# note that for this check to work, we need to fill the SlimMFT with the
# filenames, something we normally do _not_ do in the Vue tree
function _sanity_check(tree::VueNode) :: Bool
    if !isempty(tree.children)
        for c in tree.children
            if isempty(c.children) # leaf node
                @assert c.object.objecttype == "ROA"
                #check tree.siblings for MFT
                for s in tree.mates
                    if s.object.objecttype == "MFT"
                        @assert basename(c.object.filename) in s.object.object.files
                        break # break out of for s
                    end
                end
            else
                # not a leaf node, so this is a CER
                # should be on the mft of the parent CER as well then
                @assert c.object.objecttype == "CER"
                    #check tree.siblings for MFT
                    for s in tree.mates
                        if s.object.objecttype == "MFT"
                            @assert basename(c.object.filename) in s.object.object.files
                            break # break out of for s
                        end
                    end
                _sanity_check(c)
            end
        end
    end
    return true
end
function to_vue_tree(branches::Vector)
    if length(branches) < 2
        return branches
    end

    # We will iterate over all the branches from 'left to right', merging the
    # right one to the left one. By sorting them first, we ensure we always have
    # a longer left branch.
    sort!(branches, by = x -> length(x), rev=true)
    
    # Start with the longest branch, call that the 'left branch"
    # merge in every next 'right branch'
    left = branches[1]
    for b in (2:length(branches)) 
        #@debug "---"
        right = branches[b]

        # l and r point to the current node in the left and right branches we
        # are trying to merge, and will be updated to point to their immediate
        # successor in every iteration:
        l = left
        r = right
        prev_l = prev_r = nothing

        done = false
        while ! done
            # r.children can be empty. Not for ROA results (after an ASN or
            # prefix search), the ROAs on the right will be attached to the left
            # branch as soon as their direct parent (the CER) is pushed and we
            # `continue` out of the loop.
            # But for other results (search on filename), we should have used
            # to_vue_leaf_node before doing any branch+tree generation.

            if isempty(r.children)
                # assuming we are merging e.g. filename search results
                @debug "pushing $(r.name) to $(prev_l.name) children"
                push!(prev_l.children, r)
                done = true
                continue
                #throw("illegal code path")
            end

            # As long as the right node is the same as the left, we do nothing
            # But if the right filename matches nothing in the left's
            # children, we attach it to the left and are done with this right
            # branch
            # (note that initially, the number of children on left is 1
            # but because of this loop, it possibly increases)
            @assert length(r.children) == 1
            if isnothing(findfirst(x -> x.object.filename == r.children[1].object.filename, l.children))
                @assert l.name == r.name == "root" || prev_l.name == prev_r.name
                push!(l.children, r.children[1])
                done = true
                continue
            else
                # progress to the successor in both branches, and repeat:
                prev_l = l
                prev_r = r
                l = l.children[findfirst(x -> x.object.filename == r.children[1].object.filename, l.children)]
                r = r.children[1]
            end
        end
    end

    left
end

end # module
