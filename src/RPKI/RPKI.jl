module RPKI
using JDR: CFG
using JDR.Common: Remark, RemarkCounts_t, split_scheme_uri, count_remarks, AutSysNum, IPRange
using JDR.Common: remark_missingFile!, remark_loopIssue!, remark_manifestIssue!, remark_validityIssue!
using JDR.RPKICommon: add_resource!, RPKIObject, RPKINode, Lookup, TmpParseInfo, add_filename!
using JDR.RPKICommon: CER, add_resource, MFT, CRL, ROA, add_missing_filename!, RootCER, get_pubpoint
using JDR.RPKICommon: get_object, rsync, rrdp, parse_tal
using JDR.ASN1: Node

using IntervalTrees: IntervalValue
using Sockets: IPAddr

export process_tas, process_ta, process_cer, link_resources!


include("rsync.jl")
include("RRDP.jl")


"""
    check_ASN1

Validate ASN1 structure of an [`RPKIObject`](@ref). Method definitions in [CER.jl](@ref) etc.
"""
function check_ASN1 end
function check_cert end
function check_resources end

include("CER.jl")
include("MFT.jl")
include("ROA.jl")
include("CRL.jl")

function add(p::RPKINode, c::RPKINode)#, o::RPKIObject)
    c.parent = p
    p.remark_counts_children += c.remark_counts_me + c.remark_counts_children
    if isnothing(p.children)
        p.children = [c]
    else
        push!(p.children, c)
    end
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
            @warn "[$(get_pubpoint(cer_node))] Missing file: $(f)"
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
                sub_cer_node = process_cer(subcer_fn, lookup, tpi)
                add(mft_node, sub_cer_node)
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
    if isnothing(cer.children)
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
            #@warn "not linking EE -> VRP" maxlog=3
            
            # now we can get rid of the EE tree, roa.resources_v6/_v4
            #@warn "setting EE resources to nothing" maxlog=3
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

    if !isnothing(tpi.tal)
        if cer_obj.object.rsa_modulus != tpi.tal.key
            remark_validityIssue!(cer_obj, "key does not match TAL")
            @error "Certificate key does not match key in TAL: $(cer_fn)"
        end
        tpi.tal = nothing
    end


    push!(tpi.certStack, cer_obj.object)
    check_cert(cer_obj, tpi)
    check_resources(cer_obj, tpi)

    mft_host, mft_path = split_scheme_uri(cer_obj.object.manifest)
    mft_fn = joinpath(tpi.data_dir, mft_host, mft_path)
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

    (ca_host, ca_path) = if tpi.transport == rsync
        split_scheme_uri(cer_obj.object.pubpoint)
    elseif tpi.transport == rrdp
        if !isempty(cer_obj.object.rrdp_notify)
            split_scheme_uri(cer_obj.object.rrdp_notify)
        else
            @warn "No RRDP SIA for $(cer_fn), rsync SIA is $(cer_obj.object.pubpoint)"
            #(nothing, nothing)
            pop!(tpi.certStack)
            return cer_node
        end
    end

    
    rsync_module = joinpath(ca_host, splitpath(ca_path)[1])
    depth = length(tpi.certStack)
    if tpi.transport == rrdp && !(ca_host in keys(lookup.pubpoints)) ||
        tpi.transport == rsync && !(rsync_module in keys(lookup.rsync_modules))
        lookup.pubpoints[ca_host] = depth => Set(cer_node)
        if tpi.fetch_data
            if tpi.transport == rsync
                @debug "rsync, $(rsync_module) not seen before"
                Rsync.fetch_all(ca_host, ca_path)
                lookup.rsync_modules[rsync_module] = cer_fn
            elseif tpi.transport == rrdp
                rrdp_update = RRDP.fetch_process_notification(cer_node)
                RRDP.add(lookup, rrdp_update)
            end
        end
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

    if tpi.stripTree
        cer_obj.tree = nothing
    end

    #TODO: should we still process through the directory, even though there was
    #no manifest?
    if !isfile(mft_fn)
        @error "[$(get_pubpoint(cer_node))] manifest $(basename(mft_fn)) not found"
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
    pop!(tpi.certStack)
    cer_node
end


"""
	process_ta(ta_cer_fn::String; kw...)

Takes a first cerficate to parse and processes all related descending files.
Called by [`process_tas`](@ref).


Optional keyword arguments:

 - `repodir::String` -- defaults to `CFG["rpki"]["rsyncrepo"]`, i.e. the `JDR.toml` config file.
    Useful for processing data that is stored in a non-default directory structure, for
    example when the TA certificate is stored in a different directory than the RPKI files.
 - `lookup` -- defaults to an empty `Lookup()`
 - `stripTree::Bool` -- drop the ASN.1 tree from objects after validation, defaults to `false`
 - `nicenames::Bool` -- enrich the ASN.1 tree with human-readable fieldnames, defaults to `true`

Returns `Tuple{`[`RPKINode`](@ref)`,`[`Lookup`](@ref)`}`
"""
function process_ta(ta_cer_fn::String; tal=nothing, lookup=Lookup(), tpi_args...) :: Tuple{RPKINode, Lookup}
    @debug "process_ta for $(basename(ta_cer_fn))"
    if haskey(tpi_args, :data_dir)
        @debug "using custom data_dir $(data_dir)"
    end
    @assert isfile(ta_cer_fn) "Can not open file $(ta_cer_fn)"

    tpi = TmpParseInfo(;lookup, tal, tpi_args...)

    if !isdir(tpi.data_dir)
        if !tpi.fetch_data 
            @error "Can not find directory $(tpi.data_dir) and not creating/fetching anything"
            throw("invalid configuration")
        end
    end


    # get rsync url from tal
    #
    rir_root = RPKINode()
    try
        rir_root = process_cer(ta_cer_fn, lookup, tpi)
    catch e
        @error "error while processing $(ta_cer_fn)"
        @error e
        display(stacktrace(catch_backtrace()))
        rethrow(e)
    end

    # 'fetch' cer from TAL ?
    # check TA signature (new)
    # process first cer, using data_dir
    return rir_root, lookup
end

"""
    process_tas([tal_urls::Dict]; kw...)

Process all trust anchors configured in `JDR.toml`. This is likely the most common way to
start doing anything using `JDR.jl`:

```julia
using JDR;
(tree, lookup) = process_tas()
```

Optionally, a `Dict` of similar form can be passed directly to specify trust anchors not in
the configuration file, or a subset of those that are specified.

Optional keyword arguments:

 - `repodir::String` -- defaults to `CFG["rpki"]["rsyncrepo"]`, i.e. the `JDR.toml` config file. 
 - `stripTree::Bool` -- drop the ASN.1 tree from objects after validation, defaults to `false`
 - `nicenames::Bool` -- enrich the ASN.1 tree with human-readable fieldnames, defaults to `true`

Returns `Tuple{`[`RPKINode`](@ref)`,`[`Lookup`](@ref)`}`

"""
function process_tas(tals=CFG["rpki"]["tals"]; tpi_args...) :: Union{Nothing, Tuple{RPKINode, Lookup}}
    if isempty(tals)
        @warn "No TALs configured, please create/edit JDR.toml and run

            JDR.Config.generate_config()

        "
        return nothing
    end

    _tpi = TmpParseInfo(; tpi_args...)

    if _tpi.fetch_data
        if !isdir(_tpi.data_dir)
            @info "Configured data directory $(_tpi.data_dir) does not exist, will try to create it"
            try
                mkpath(_tpi.data_dir)
            catch e
                @warn "Failed to create $(_tpi.data_dir): ", e
            end
        else
            # we fetch full snapshots for RRDP, so we start with a clean slate every fetch
            # for rsync we want to keep the old dir around to reduce transfer delays
            #if _tpi.transport == rrdp
            #    @info "Configured RRDP data directory exists, moving it to .prev"
            #    try
            #        dir = _tpi.data_dir
            #        if isdirpath(dir)
            #            # contains trailing slash, chop it off
            #            dir = dirname(dir)
            #        end

            #        mv(dir, dir*".prev"; force=true)
            #    catch e
            #        @warn "Failed to move $(dir) to $(dir).prev : ", e
            #    end
            #end
        end
    end

    lookup = Lookup()
    rpki_root = RPKINode()
    rpki_root.obj = RPKIObject{RootCER}()

    tasks = Vector{Task}()
    results = Channel(10)

    for (talname, tal_fn) in tals
        @debug "for talname: $(talname)"
        tal = parse_tal(joinpath(CFG["rpki"]["tal_dir"], tal_fn))
        cer_uri = if _tpi.transport == rsync
            tal.rsync
        elseif _tpi.transport == rrdp
            if isnothing(tal.rrdp)
                @warn "No RRDP URI for tal $(talname), skipping"
                continue
            end
            tal.rrdp
        end

        (hostname, cer_fn) = split_scheme_uri(cer_uri) 
        ta_cer_fn = joinpath(_tpi.data_dir, "tmp", hostname, cer_fn)
        if !isfile(ta_cer_fn)
            if _tpi.fetch_data
                if _tpi.transport == rrdp
                    RRDP.fetch_ta_cer(cer_uri, ta_cer_fn)
                else
                    Rsync.fetch_ta_cer(cer_uri, ta_cer_fn)
                end
            else
                @warn "TA certificate for $(talname) not locally available and not fetching
                in this run. Consider passing `fetch_data=true`."
                continue
            end
        end

        work() = try 
            @info "Processing $(talname)"
            put!(results, process_ta(ta_cer_fn; lookup, tal, tpi_args...))
            @info "Done processing $(talname)"
        catch e
            @error ta_cer_fn e
            if e isa InterruptException
                put!(results, ErrorException("Processing $(talname) timed out"))
            else
                put!(results, ErrorException("Failed to process $(talname), $(e)"))
            end
        end
        task = Task(work)
        push!(tasks, task)
        schedule(task)

    end

    status = timedwait(() -> all(istaskdone, tasks), 180)
    if status == :timed_out
        @warn "One or more tasks timed out"
        for t_to in filter(t->!istaskdone(t), tasks)
            schedule(t_to, InterruptException(); error=true)
        end
    end
    processed = 0
    while isready(results)
        res = take!(results)
        if res isa ErrorException 
            @warn res.msg
        else
            (rir_root, lkup) = res
            add(rpki_root, rir_root)
            processed += 1
            @info "TAL $(processed)/$(length(tals)) merged: $(rir_root)"
        end
    end
    @info "Done, $(processed)/$(length(tals)) merged successfully"

    rpki_root, lookup
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
