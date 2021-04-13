module RPKI
using ..JDR
using ..JDR.Common
using ..JDR.RPKICommon
using ..ASN1

using IPNets
using Sockets
using Dates
using SHA
using IntervalTrees


export search, RPKINode, RPKIObject # reexport from RPKI.Common
export retrieve_all, RootCER, CER, MFT, CRL, ROA
export TmpParseInfo
export print_ASN1

function check_ASN1 end
function check_cert end
function check_resources end

include("CER.jl")
using .Cer
include("MFT.jl")
using .Mft
include("ROA.jl")
using .Roa
include("CRL.jl")
using .Crl


function RPKIObject(filename::String)::RPKIObject
    tree = DER.parse_file_recursive(filename)
    ext = lowercase(filename[end-3:end])
    if      ext == ".cer" RPKIObject{CER}(filename, tree)
    elseif  ext == ".mft" RPKIObject{MFT}(filename, tree)
    elseif  ext == ".roa" RPKIObject{ROA}(filename, tree)
    elseif  ext == ".crl" RPKIObject{CRL}(filename, tree)
    end
end
function RPKIObject{T}(filename::String)::RPKIObject{T} where T
    tree = DER.parse_file_recursive(filename)
    RPKIObject{T}(filename, tree)
end


function add(p::RPKINode, c::RPKINode)#, o::RPKIObject)
    c.parent = p
    p.remark_counts_children += c.remark_counts_me + c.remark_counts_children
    push!(p.children, c)
end
function add(p::RPKINode, c::Vector{RPKINode})
    for child in c
        add(p, child)
    end
end

function add_sibling(a::RPKINode, b::RPKINode)
    if isnothing(a.siblings)
        a.siblings = RPKINode[b]
    else
        push!(a.siblings, b)
    end
    if isnothing(b.siblings)
        b.siblings = RPKINode[a]
    else
        push!(b.siblings, a)
    end
end

function check(::RPKIObject{T}) where {T}
    @warn "unknown RPKIObject type $(T)"
end


function add_roa!(lookup::Lookup, roanode::RPKINode)
    # TODO do we also want to add CERs here?
    @assert roanode.obj isa RPKIObject{ROA}
    roa = roanode.obj.object
    asn = AutSysNum(roa.asid)
    if asn in keys(lookup.ASNs)
        push!(lookup.ASNs[asn], roanode) 
    else
        lookup.ASNs[asn] = [roanode]
    end
end

function process_roa(roa_fn::String, lookup::Lookup, tpi::TmpParseInfo) :: RPKINode
    roa_obj::RPKIObject{ROA} = check_ASN1(RPKIObject{ROA}(roa_fn), tpi)
    roa_node = RPKINode(roa_obj)
    add_filename!(lookup, roa_fn, roa_node)

    # add EE resources to Lookup
    for r in roa_obj.object.resources_v4
        add_resource(lookup, r.first, r.last, roa_node)
    end
    for r in roa_obj.object.resources_v6
        add_resource(lookup, r.first, r.last, roa_node)
    end

    # add VRPs to Lookup
    for r in roa_obj.object.vrp_tree.resources_v4
        add_resource(lookup, r.first, r.last, roa_node)
    end
    for r in roa_obj.object.vrp_tree.resources_v6
        add_resource(lookup, r.first, r.last, roa_node)
    end
    

    roa_node.remark_counts_me = count_remarks(roa_obj)

    @assert !isnothing(tpi.eeCert)
    check_cert(roa_obj, tpi)
    check_resources(roa_obj, tpi)

    # optionally strip the tree to save memory
    if tpi.stripTree
        roa_obj.tree = nothing
    end
    roa_node
end

struct LoopError <: Exception 
    file1::String
    file2::String
end
LoopError(file1::String) = LoopError(file1, "")
Base.showerror(io::IO, e::LoopError) = print(io, "loop between ", e.file1, " and ", e.file2)

function process_crl(crl_fn::String, lookup::Lookup, tpi::TmpParseInfo) ::RPKINode
    crl_obj::RPKIObject{CRL} = check_ASN1(RPKIObject{CRL}(crl_fn), tpi)
    check_cert(crl_obj, tpi)
    crl_node = RPKINode(crl_obj)
    add_filename!(lookup, crl_fn, crl_node)
    crl_node.remark_counts_me = count_remarks(crl_obj)
    if tpi.stripTree
        crl_obj.tree = nothing
    end
    crl_node
end

function process_mft(mft_fn::String, lookup::Lookup, tpi::TmpParseInfo, cer_node::RPKINode) :: RPKINode
    mft_dir = dirname(mft_fn)
    tpi.cwd = mft_dir
    mft_obj::RPKIObject{MFT} = try 
        check_ASN1(RPKIObject{MFT}(mft_fn), tpi)
    catch e 
        showerror(stderr, e, catch_backtrace())
        @error "MFT: error with $(mft_fn)"
        return RPKINode()
    end
	crl_count = 0

    check_cert(mft_obj, tpi)

    mft_node = RPKINode(mft_obj)
    # we add the remarks_counts for the mft_obj after we actually processed the
    # fileList on the manifest, as more remarks might be added there
    if tpi.stripTree
        mft_obj.tree = nothing 
    end

    for f in mft_obj.object.files
        if !isfile(joinpath(mft_dir, f))
            @warn "[$(RPKICommon.get_pubpoint(cer_node))] Missing file: $(f)"
            Mft.add_missing_file(mft_obj.object, f)
            add_missing_filename!(lookup, joinpath(mft_dir, f), mft_node)
            remark_missingFile!(mft_obj, "Listed in manifest but missing on file system: $(f)")
            continue
        end
        if endswith(f, r"\.cer"i)
            # TODO accomodate for BGPsec router certificates
            subcer_fn = joinpath(mft_dir, f)
            try
                # TODO
                # can .cer and .roa files be in the same dir / on the same level
                # of a manifest? in other words, can we be sure that if we reach
                # this part of the `if ext ==`, there will be no other files to
                # check?

                #if subcer_fn in keys(lookup.filenames)
                #    @warn "$(subcer_fn) already seen, loop?"
                #    throw("possible loop in $(subcer_fn)" )
                #end
                #@debug "process_cer from _mft for $(basename(subcer_fn))"
                cer_node = process_cer(subcer_fn, lookup, tpi)
                add(mft_node, cer_node)
            catch e
                if e isa LoopError
                    #@warn "LoopError, trying to continue"
                    #@warn "but pushing $(basename(subcer_fn))"

                    if isnothing(mft_obj.object.loops)
                        mft_obj.object.loops = [basename(subcer_fn)]
                    else
                        push!(mft_obj.object.loops, basename(subcer_fn))
                    end
                    remark_loopIssue!(mft_obj, "Loop detected with $(basename(subcer_fn))")
                    #@warn "so now it is $(m.object.loops)"
                else
                    #throw("MFT->.cer: error with $(subcer_fn): \n $(e)")
                    rethrow(e)
                    #showerror(stderr, e, catch_backtrace())
                end
            end
        elseif endswith(f, r"\.roa"i)
            roa_fn = joinpath(mft_dir, f)
            try
                roa_node = process_roa(roa_fn, lookup, tpi)
                add(mft_node, roa_node)
                add_roa!(lookup, roa_node)
            catch e
                #showerror(stderr, e, catch_backtrace())
                #throw("MFT->.roa: error with $(roa_fn): \n $(e)")
                rethrow(e)
            end
        elseif endswith(f, r"\.crl"i)
            crl_fn = joinpath(mft_dir, f)
            crl_count += 1
            if crl_count > 1
                @error "more than one CRL on $(mft_fn)"
                remark_manifestIssue!(mft_obj, "More than one CRL on this manifest")
            end
            try
                crl_node = process_crl(crl_fn, lookup, tpi)
                add(mft_node, crl_node)
                add_sibling(cer_node, crl_node)
            catch e
                rethrow(e)
            end
        end

    end

    # returning:
    mft_node.remark_counts_me = count_remarks(mft_obj) 
    add_filename!(lookup, mft_fn, mft_node)
    mft_node
end

function link_resources!(cer::RPKINode)
    if isempty(cer.children)
        return
    end

    # There are two cases when traversing down the RPKINode tree:
    # 1: a CER points, via an MFT (.children[1]), to children
    # 2: the RootCER points to RIR CERs directly
    descendants = if cer.children[1].obj.object isa MFT
        # case 1
        cer.children[1].children
    elseif cer.obj.object isa RootCER
        # case 2
        cer.children
    end
    for child in filter(x->x.obj.object isa Union{CER,ROA}, descendants)
        overlap = intersect(cer.obj.object.resources_v6, child.obj.object.resources_v6)
        for (p, c) in overlap
            push!(p.value, child) # add RPKINode pointing to child to this interval.value
        end
        overlap = intersect(cer.obj.object.resources_v4, child.obj.object.resources_v4)
        for (p, c) in overlap
            push!(p.value, child) # add RPKINode pointing to child to this interval.value
        end
        if child.obj.object isa CER
            link_resources!(child)
        elseif child.obj.object isa ROA
            @warn "not linking EE -> VRP" maxlog=3
            
            # now we can get rid of the EE tree, roa.resources_v6/_v4
            @warn "setting EE resources to nothing" maxlog=3
            child.obj.object.resources_v6 = nothing
            child.obj.object.resources_v4 = nothing
        end
    end
end

function process_cer(cer_fn::String, lookup::Lookup, tpi::TmpParseInfo) :: RPKINode
    # now, for each .cer, get the CA Repo and 'sync' again
    if cer_fn in keys(lookup.filenames)
        @warn "$(basename(cer_fn)) already seen, loop?"
        throw(LoopError(cer_fn))
    else
        # placeholder: we need to put something in because when a loop appears
        # in the RPKI repo, this call will never finish so adding it at the end
        # of this function will never happen.
        add_filename!(lookup, cer_fn, RPKINode())
    end

    cer_obj::RPKIObject{CER} = check_ASN1(RPKIObject{CER}(cer_fn), tpi)

    push!(tpi.certStack, cer_obj.object)
    check_cert(cer_obj, tpi)
    check_resources(cer_obj, tpi)

    (ca_host, ca_path) = split_scheme_uri(cer_obj.object.pubpoint)
    ca_dir = joinpath(tpi.repodir, ca_host, ca_path)
    
    mft_host, mft_path = split_scheme_uri(cer_obj.object.manifest)
    mft_fn = joinpath(tpi.repodir, mft_host, mft_path)
    cer_node = RPKINode(cer_obj)

    if cer_obj.sig_valid 
        push!(lookup.valid_certs, cer_node)
    else
        push!(lookup.invalid_certs, cer_node)
    end

    for r in cer_obj.object.resources_v4
        add_resource(lookup, r.first, r.last, cer_node)
    end
    for r in cer_obj.object.resources_v6
        add_resource(lookup, r.first, r.last, cer_node)
    end

    depth = length(tpi.certStack)
    if !(ca_host in keys(lookup.pubpoints))
        lookup.pubpoints[ca_host] = depth => Set(cer_node)
    else
        (d, s) = lookup.pubpoints[ca_host]
        if depth < d
            @debug "existing pubpoint $(ca_host) at lower degree $(depth) instead of $(d)"
            lookup.pubpoints[ca_host] = depth => Set(cer_node)
        elseif depth == d
            #@debug "existing pubpoint $(ca_host) at similar depth $(depth)"
            #(_, set) = lookup.pubpoints[ca_host] 
            push!(s, cer_node)
        end
    end
    #= # for now, do not add the RRDP hosts to lookup.pubpoints
    if !(isempty(cer_obj.object.rrdp_notify))
        (rrdp_host, _) = split_rrdp_path(cer_obj.object.rrdp_notify)
        if !(rrdp_host in keys(lookup.pubpoints))
            lookup.pubpoints[rrdp_host] = cer_node
        end
    end
    =#

    if tpi.stripTree
        cer_obj.tree = nothing
    end

    #TODO: should we still process through the directory, even though there was
    #no manifest?
    if !isfile(mft_fn)
        @error "[$(RPKICommon.get_pubpoint(cer_node))] manifest $(basename(mft_fn)) not found"
        add_missing_filename!(lookup, mft_fn, cer_node)
        remark_missingFile!(cer_obj, "Manifest file $(basename(mft_fn)) not in repo")
    else

        try
            mft = process_mft(mft_fn, lookup, tpi, cer_node)
            add(cer_node, mft)
        catch e
            if e isa LoopError
                @warn "Loop! between $(basename(e.file1)) and $(basename(e.file2))"
            else
                rethrow(e)
            end
        end
    end

    # we already counted the remarks from .tree, now add those from the object:
    cer_node.remark_counts_me = count_remarks(cer_obj)

    add_filename!(lookup, cer_fn, cer_node)
    pop!(tpi.issuer)
    pop!(tpi.certStack)
    cer_node
end


function _merge_RIRs(a::RPKINode, b::RPKINode) :: RPKINode
    # check the first RPKINode begin "root", i.e. no attached .obj
    @assert isnothing(a.obj)
    @assert isnothing(b.obj)
    @assert length(b.children) == 1

    push!(a.children, b.children[1]) 
    a
end

function _merge_lookups(a::Lookup, b::Lookup) ::Lookup
    for property in propertynames(a)
        #TODO prefix_tree_ is replaced with :resources_v IntervalTree
        if property == :prefix_tree_v6 || property == :prefix_tree_v4
            continue
        end
        if getproperty(a, property) isa Vector
            append!(getproperty(a, property), getproperty(b, property))
        else
            #mergewith!(Base.append!, getproperty(a, property), getproperty(b, property))
            merge!(getproperty(a, property), getproperty(b, property))
        end
    end
    #mergewith!(append!, a.filenames, b.filenames)
    a
end

# processes all the data on disk under a single TA
# based on a specific TA-path and repodir?
# based on config, thus only needing a TA Symbol name as input?
function process_ta(ta_cer_fn::String, repodir::String; stripTree::Bool=false, nicenames=true) :: Tuple{RPKINode, Lookup}
    @debug "process_tal for $(basename(ta_cer_fn)) with repodir $(repodir)"
    @assert isfile(ta_cer_fn)
    @assert isdir(repodir)

    # get rsync url from tal
    #
    lookup = Lookup()
    root = RPKINode()
    #(hostname, cer_fn) = split_scheme_uri(rsync_url)  
    try
        add(root, process_cer(ta_cer_fn, lookup, TmpParseInfo(;repodir,lookup,stripTree,nicenames)))
    catch e
        @error "error while processing $(ta_cer_fn)"
        @error e
        display(stacktrace(catch_backtrace()))
        rethrow(e)
    end

    # 'fetch' cer from TAL ?
    # check TA signature (new)
    # process first cer, using repodir
    return root, lookup
end

function _glue_rootnode(tree::RPKINode) :: RPKINode
    @assert isnothing(tree.obj) "Root node already glued?"
    rootobj = RPKIObject{RootCER}()
    push!(rootobj.object.resources_v6, IntervalValue(IPRange("::/0"), [e for e in tree.children]))
    push!(rootobj.object.resources_v4, IntervalValue(IPRange("0.0.0.0/0"), [e for e in tree.children]))
    tree.obj = rootobj
    tree
end

function retrieve_all(tal_urls=JDR.CFG["rpki"]["tals"]; stripTree::Bool=false, nicenames=true) :: Tuple{RPKINode, Lookup}
    branches = RPKINode[]
    lookup = Lookup()

    for (rir, rsync_url) in collect(tal_urls)
        root = RPKINode()
        (hostname, cer_fn) = split_scheme_uri(rsync_url)  
        rir_dir = joinpath(JDR.CFG["rpki"]["rsyncrepo"], hostname)

        # For now, we rely on Routinator for the actual fetching
        # We do however construct all the paths and mimic the entire procedure
        if !isdir(rir_dir)
            @error "repo dir not found: $(rir_dir)"
            @assert isdir(rir_dir)
        end

        # 'rsync' the .cer from the TAL
        ta_cer = joinpath(rir_dir, cer_fn)
        @info "Processing $(rir) on thread $(Threads.threadid())"
        @debug ta_cer
        @assert isfile(ta_cer)

        # start recursing
        try
            add(root, process_cer(ta_cer, lookup, TmpParseInfo(;lookup,stripTree,nicenames)))
        catch e
            # TODO: what is a proper way to record the error, but continue with
            # the rest of the repo?
            # maybe a 'hard error counter' per RIR/pubpoint ?
            # also revisit the try/catches in process_cer()
            
            @error "error while processing $(ta_cer)"
            @error e
            display(stacktrace(catch_backtrace()))

            rethrow(e)
        end
        @info "pushing branch for $(rir) from thread $(Threads.threadid())"
        push!(branches, root)
    end

    (reduce(_merge_RIRs, branches) |> _glue_rootnode, lookup)
end

function _pubpoints!(pp_tree::RPKINode, tree::RPKINode, current_pp::String)

    if isempty(tree.children)
        #@debug "isempty tree.children"
        return #pp_tree
    end

    #@debug "tree:", typeof(tree.obj).parameters[1]
    for c in tree.children
        if !isnothing(c.obj )
            #@debug typeof(c.obj).parameters[1]
        end
        if c.obj isa RPKIObject{CER}
            #@debug "found CER child", c.obj
            #@debug "c.obj.object", c.obj.object
            this_pp = split_scheme_uri(c.obj.object.pubpoint)[1]
            if this_pp != current_pp
                # FIXME check if this_pp exists on the same level
                if this_pp in [c2.obj for c2 in pp_tree.children]
                    #@debug "new but duplicate: $(this_pp)"
                    _pubpoints!(pp_tree, c, this_pp)
                else
                    new_pp = RPKINode(nothing, [], this_pp)
                    _pubpoints!(new_pp, c, this_pp)
                    add(pp_tree, new_pp)
                end
            else
                #@debug "found same pubpoint as parent: $(this_pp)"
                #add(pp_tree, _pubpoints(c, this_pp))
                _pubpoints!(pp_tree, c, current_pp)
            end
        elseif c.obj isa RPKIObject{MFT}
            #@debug "elseif MFT"
            #add(pp_tree, _pubpoints(c, current_pp))
            #return _pubpoints(c, current_pp)
            _pubpoints!(pp_tree, c, current_pp)
        else
            #@debug "found non-CER/MFT child:", c.obj
            #add(pp_tree, _pubpoints(c, current_pp))
            #return _pubpoints(c, current_pp)

            _pubpoints!(pp_tree, c, current_pp)
        end
    end
end

function pubpoints(tree::RPKINode) :: RPKINode
    pp_tree = RPKINode(nothing, [], "root")
    for c in tree.children
        if ! isnothing(c.obj) && c.obj isa RPKIObject{CER}
            pp = split_scheme_uri(c.obj.object.pubpoint)[1]
            subtree = RPKINode(nothing, [], pp)
            _pubpoints!(subtree, c, pp)
            add(pp_tree, subtree)
        end
    end
    pp_tree
end


function collect_remarks_from_asn1!(o::RPKIObject{T}, node::Node) where T
    if !isnothing(node.remarks)
        if isnothing(o.remarks_tree)
            o.remarks_tree = []
        end
        Base.append!(o.remarks_tree, node.remarks)
    end
    if !isnothing(node.children)
        for c in node.children
            collect_remarks_from_asn1!(o, c)
        end
    end
end

end # module
