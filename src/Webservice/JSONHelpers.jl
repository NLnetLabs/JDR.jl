using JDR.ASN1
using JDR.RPKICommon

using Sockets
using IntervalTrees # for IP prefixes on certificates

details_url(filename::String) = CFG["webservice"]["domain"] * "/api/v1/object/" * HTTP.escapeuri(filename)
details_url(n::RPKINode) = details_url(n.obj.filename)
details_url(o::RPKIObject{T}) where T = details_url(o.filename)

StructTypes.StructType(::Type{RPKI.RPKINode}) = StructTypes.Struct()
StructTypes.excludes(::Type{RPKI.RPKINode}) = (:parent, :siblings)

StructTypes.StructType(::Type{RPKI.RPKIObject}) = StructTypes.Struct()
StructTypes.excludes(::Type{RPKI.RPKIObject}) = (:tree,) #TODO perhaps omitempties suffices here, because we do stripTree?

StructTypes.StructType(::Type{ASN1.Node}) = StructTypes.Struct()
StructTypes.excludes(::Type{ASN1.Node}) = (:buf,)

StructTypes.StructType(::Type{RPKI.ROA}) = StructTypes.Struct()
StructTypes.excludes(::Type{RPKI.ROA}) = (:resources_v6, :resources_v4)
StructTypes.names(::Type{RPKI.ROA}) = ((:vrp_tree, :vrps),)


function _serialize_linked_resource(i::IntervalValue{<:IPAddr, Vector{RPKINode}})
    # string(i) is the prefix
    # value(i) is the Vector of RPKINodes
    cers = filter(e->e.obj.object isa RPKI.CER, value(i)) |> unique
    roas = filter(e->e.obj.object isa RPKI.ROA, value(i)) |> unique
    Dict("prefix" => string(i),
         "CERs" => map(e->e.obj.filename, cers),
         "ROAs" => map(e->e.obj.filename, roas)
        )
end
function _serialize_linked_resources(res::RPKICommon.LinkedResources)
    map(_serialize_linked_resource, collect(res))
end
StructTypes.StructType(::Type{<:RPKICommon.LinkedResources}) = StructTypes.CustomStruct()
StructTypes.lower(x::RPKICommon.LinkedResources) = _serialize_linked_resources(x)
StructTypes.lowertype(::Type{<:RPKICommon.LinkedResources}) = Vector


#TODO must be adapted to also feature 'empty' maxlens
function _serialize_vrps(vrps::RPKICommon._VRPS)
    ["$(string(v))-$(value(v))" for v in vrps]
end
StructTypes.StructType(::Type{RPKICommon.VRPS}) = StructTypes.Struct()
StructTypes.StructType(::Type{<:RPKICommon._VRPS}) = StructTypes.CustomStruct()
StructTypes.lower(x::RPKICommon._VRPS) = _serialize_vrps(x)
StructTypes.lowertype(::Type{RPKICommon._VRPS}) = Vector

# custom view for RPKIObject{T}
# includes the tree, but does not link to parent or children
# TODO: do we still need this, with the .excludes on those fields?
struct ObjectDetails{T}
    filename::String
    path::String
    tree::RPKI.Node
    object::T
    objecttype::String
    remarks::Union{Nothing, Vector{RPKI.Remark}}
    remark_counts_me::Union{Nothing, RemarkCounts_t}
    remarks_tree::Union{Nothing, Vector{RPKI.Remark}}
    sig_valid::Union{Nothing, Bool}
end

StructTypes.StructType(::Type{RPKI.Remark}) = StructTypes.Struct()
StructTypes.StructType(::Type{RPKI.RemarkCounts_t}) = StructTypes.DictType()

function ObjectDetails(r::RPKI.RPKIObject, rc::Union{Nothing, RemarkCounts_t})
    # we parse this again, because it is removed from the main tree/lookup 
    tmp = RPKI.RPKIObject(r.filename)
    RPKI.check_ASN1(tmp, RPKI.TmpParseInfo(;nicenames=true, oneshot=true))
    @assert isnothing(tmp.remarks_tree)
    RPKI.collect_remarks_from_asn1!(tmp, tmp.tree)
    
    d = ObjectDetails(basename(r.filename),
                      dirname(r.filename),
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
StructTypes.StructType(::Type{RPKI.CER}) = StructTypes.Struct()
StructTypes.excludes(::Type{RPKI.CER}) = (:rsa_modulus, )
StructTypes.StructType(::Type{AutSysNum}) = StructTypes.Struct()
StructTypes.StructType(::Type{AutSysNumRange}) = StructTypes.Struct()


StructTypes.StructType(::Type{RPKI.MFT}) = StructTypes.Struct()
StructTypes.StructType(::Type{RPKI.CRL}) = StructTypes.Struct()
StructTypes.StructType(::Type{RPKICommon.SerialNumber}) = StructTypes.StringType()

StructTypes.StructType(::Type{<:ObjectDetails}) = StructTypes.Struct()

struct ObjectSlim{T}
    filename::String
    depr_details_url::String # this is only for ease of development
    object::T # FIXME force this to be a SlimCER or SlimMFT etc
    objecttype::String
    depr_remarks::Union{Nothing, Vector{RPKI.Remark}}
    remark_counts_me::Union{Nothing, RemarkCounts_t}
    remark_counts_children::Union{Nothing, RemarkCounts_t}
end


struct RemarkDeeplink
    lvl::RemarkLevel
    type::RemarkType
    msg::String
    tid::Int
    filename::String
end
RemarkDeeplink(r::Remark, filename::String) = RemarkDeeplink(r.lvl, r.type, r.msg, r.tid, filename)

StructTypes.StructType(::Type{RemarkDeeplink}) = StructTypes.Struct()

function ObjectSlim(r::RPKI.RPKIObject, rcm::Union{Nothing, RemarkCounts_t}, rcc::Union{Nothing, RemarkCounts_t})
    ObjectSlim(r.filename,
               details_url(r.filename),
               to_slim(r.object),
               string(nameof(typeof(r.object))),
               r.remarks,
               rcm, # FIXME assert r.remarks ==~ rcm
               rcc
            )
end
StructTypes.StructType(::Type{<:ObjectSlim}) = StructTypes.Struct()

StructTypes.StructType(::Type{ASN1.Tag}) = StructTypes.StringType()


# Slim copy of RPKI.CER, with empty prefixes and ASNs Vectors
struct SlimCER 
    depr_pubpoint::String
    manifest::String
    depr_rrdp_notify::String
    depr_inherit_v6_prefixes::Union{Nothing,Bool}
    depr_inherit_v4_prefixes::Union{Nothing,Bool}
    depr_inherit_ASNs::Union{Nothing, Bool}
end
SlimCER(cer::RPKI.CER) = begin
    SlimCER(cer.pubpoint, cer.manifest, cer.rrdp_notify,
                                 cer.inherit_v6_prefixes, cer.inherit_v4_prefixes,
                                 #[],
                                 cer.inherit_ASNs)#, [])
end
StructTypes.StructType(::Type{SlimCER}) = StructTypes.Struct()

# Slim copy of RPKI.MFT, with an empty files Vector
struct SlimMFT
    loops::Union{Nothing, Vector{String}}
    missing_files::Union{Nothing, Vector{String}}
    this_update::Union{Nothing, DateTime}
    next_update::Union{Nothing, DateTime}
end

SlimMFT(mft::RPKI.MFT) = SlimMFT(mft.loops, mft.missing_files, mft.this_update, mft.next_update)
StructTypes.StructType(::Type{SlimMFT}) = StructTypes.Struct()


struct SlimCRL end
SlimCRL(crl::RPKI.CRL) = SlimCRL()

StructTypes.StructType(::Type{SlimCRL}) = StructTypes.Struct()

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

StructTypes.StructType(::Type{VueNode}) = StructTypes.Struct()
StructTypes.omitempties(::Type{VueNode}) = (:children, :mates)


function get_vue_leaf_node(node::RPKI.RPKINode) ::RPKINode
    @debug "in get_vue_leaf_node"
    if node.obj.object isa CRL
        @assert length(node.siblings) == 1
        @assert node.siblings[1].obj.object isa CER

        # the sibling CER should have exactly 1 child (the MFT), but whenever
        # that MFT is missing, we still want to serve, so we check on <= 1
        @assert length(node.siblings[1].children) <= 1
        if length(node.siblings[1].children) == 1
            @assert node.siblings[1].children[1].obj.object isa MFT
            node.siblings[1].children[1]
        else
            node.siblings[1]
        end
    elseif node.obj.object isa CER
        if !isnothing(node.children)
            @assert length(node.children) == 1
            @assert node.children[1].obj.object isa MFT
            node.children[1]
        else
            @debug "CER node but no children?", node.obj.filename
            node
        end
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
        siblings = if isnothing(n.siblings)
            []
        else
            [VueNode([], [], basename(s.obj.filename), ObjectSlim(s.obj, s.remark_counts_me, s.remark_counts_children), nothing) for s in n.siblings]
        end
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

function _pubpoints!(pp_tree::VueNode, tree::RPKI.RPKINode, current_pp::AbstractString)
    if isnothing(tree.children)
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
                # check if the node is not already in the left branch
                if !(r.object.filename in [c.object.filename for c in prev_l.children])
                    push!(prev_l.children, r)
                end
                done = true
                continue
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

#end # module
