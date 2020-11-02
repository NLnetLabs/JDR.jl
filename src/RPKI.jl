module RPKI
using ...JDR.Common
using ...JDR.RPKICommon
using ..ASN1
using ..PrefixTrees

using IPNets
using Dates
using SHA
using IntervalTrees

export RPKINode, RPKIObject # reexport from RPKI.Common
export retrieve_all, CER, MFT, CRL, ROA
export TmpParseInfo
export print_ASN1

function check_ASN1(::RPKIObject{T}, ::TmpParseInfo) where T end
function check_cert(::RPKIObject{T}, ::TmpParseInfo) where T end
function check_resources(::RPKIObject{T}, ::TmpParseInfo) where T end

include("RPKI/CER.jl")
using .Cer
include("RPKI/MFT.jl")
using .Mft
include("RPKI/ROA.jl")
using .Roa
include("RPKI/CRL.jl")
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
    ext = lowercase(filename[end-3:end])
    if      ext == ".cer" RPKIObject{CER}(filename, tree)
    elseif  ext == ".mft" RPKIObject{MFT}(filename, tree)
    elseif  ext == ".roa" RPKIObject{ROA}(filename, tree)
    elseif  ext == ".crl" RPKIObject{CRL}(filename, tree)
    end
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
    push!(a.siblings, b)
    push!(b.siblings, a)
end

function check(::RPKIObject{T}) where {T}
    @warn "unknown RPKIObject type $(T)"
end


# Retrieving and validating the entire repository 

# start at the RIR TAs
const TAL_URLS = Dict(
    :afrinic    => "rsync://rpki.afrinic.net/repository/AfriNIC.cer",
    :apnic      => "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
    :arin       => "rsync://rpki.arin.net/repository/arin-rpki-ta.cer",
    :lacnic     => "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer",
    :ripe       => "rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer",
    #:ripetest   => "rsync://localcert.ripe.net/ta/ripe-ncc-pilot.cer",
    #:apnictest  => "rsync://rpki-testbed.apnic.net/repository/apnic-rpki-root-iana-origin-test.cer"
)
REPO_DIR = joinpath(homedir(), ".rpki-cache/repository/rsync")

function add_roa!(lookup::Lookup, roanode::RPKINode)
    # add ASN
    # TODO do we also want to add CERs here?
    @assert roanode.obj isa RPKIObject{ROA}
    roa = roanode.obj.object
    asn = AutSysNum(roa.asid)
    #@assert asn > 0
    if asn in keys(lookup.ASNs)
        push!(lookup.ASNs[asn], roanode) 
    else
        lookup.ASNs[asn] = [roanode]
    end

    # add prefixes
    for vrp in roa.vrps
        if vrp.prefix isa IPv6Net
            lookup.prefix_tree_v6[vrp.prefix] = roanode
            if vrp.prefix.netmask > 48
                push!(lookup.too_specific, roanode)
            end
        elseif vrp.prefix isa IPv4Net
            lookup.prefix_tree_v4[vrp.prefix] = roanode
            if vrp.prefix.netmask > 24
                push!(lookup.too_specific, roanode)
            end
        else
            throw("illegal vrp.prefix")
        end
    end
end

function process_roa(roa_fn::String, lookup::Lookup, tpi::TmpParseInfo) :: RPKINode
    roa_obj::RPKIObject{ROA} = check_ASN1(RPKIObject{ROA}(roa_fn), tpi)
    roa_node = RPKINode(roa_obj)
    add_filename!(lookup, roa_fn, roa_node)

    roa_node.remark_counts_me = count_remarks(roa_obj) + count_remarks(roa_obj.tree)

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
    crl_node = RPKINode(crl_obj)
    add_filename!(lookup, crl_fn, crl_node)
    crl_node.remark_counts_me = count_remarks(crl_obj) + count_remarks(crl_obj.tree)
    crl_node
end

function process_mft(mft_fn::String, lookup::Lookup, tpi::TmpParseInfo, cer_node::RPKINode) :: RPKINode
    #if mft_fn in keys(lookup.filenames)
    #    @warn "$(mft_fn) already seen, loop?"
    #    throw("possible loop in $(mft_fn)" )
    #end
    mft_obj::RPKIObject{MFT} = try 
        check_ASN1(RPKIObject{MFT}(mft_fn), tpi)
    catch e 
        showerror(stderr, e, catch_backtrace())
        @error "MFT: error with $(mft_fn)"
        return RPKINode()
    end
    mft_dir = dirname(mft_fn)
    listed_files = Vector{RPKINode}()
	crl_count = 0

    check_cert(mft_obj, tpi)

    mft_node = RPKINode(mft_obj)
    # we add the remarks_counts for the mft_obj after we actually processed the
    # fileList on the manifest, as more remarks might be added there
    mft_node.remark_counts_me = count_remarks(mft_obj.tree)
    if tpi.stripTree
        mft_obj.tree = nothing 
    end

    for f in mft_obj.object.files
        if !isfile(joinpath(mft_dir, f))
            @warn "Missing file: $(f)"
            Mft.add_missing_file(mft_obj.object, f)
            add_missing_filename!(lookup, joinpath(mft_dir, f), mft_node)
            remark_missingFile!(mft_obj, "Listed in manifest but missing on file system: $(f)")
            continue
        end
        ext = lowercase(f[end-3:end])
        if ext == ".cer"
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
                cer = process_cer(subcer_fn, lookup, tpi)
                push!(listed_files, cer)
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
        elseif ext == ".roa"
            roa_fn = joinpath(mft_dir, f)
            try
                roanode = process_roa(roa_fn, lookup, tpi)
                push!(listed_files, roanode)
                add_roa!(lookup, roanode)
            catch e
                #showerror(stderr, e, catch_backtrace())
                #throw("MFT->.roa: error with $(roa_fn): \n $(e)")
                rethrow(e)
            end
        elseif ext == ".crl"
            crl_fn = joinpath(mft_dir, f)
            crl_count += 1
            if crl_count > 1
                @error "more than one CRL on $(mft_fn)"
                remark_manifestIssue!(mft_obj, "More than one CRL on this manifest")
            end
            try
                crlnode = process_crl(crl_fn, lookup, tpi)
                push!(listed_files, crlnode)
                add_sibling(cer_node, crlnode)


            catch e
                rethrow(e)
            end
        end

    end

    # returning:
    mft_node.remark_counts_me += count_remarks(mft_obj) 
    add(mft_node, listed_files)
    add_filename!(lookup, mft_fn, mft_node)
    mft_node
end

function process_cer(cer_fn::String, lookup::Lookup, tpi::TmpParseInfo) :: RPKINode
    #@debug "process_cer for $(basename(cer_fn))"
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
    ca_dir = joinpath(REPO_DIR, ca_host, ca_path)
    
    mft_host, mft_path = split_scheme_uri(cer_obj.object.manifest)
    mft_fn = joinpath(REPO_DIR, mft_host, mft_path)
    cer_node = RPKINode(cer_obj)

    if cer_obj.sig_valid 
        push!(lookup.valid_certs, cer_node)
    else
        push!(lookup.invalid_certs, cer_node)
    end

    if !(ca_host in keys(lookup.pubpoints))
        lookup.pubpoints[ca_host] = cer_node
    end
    if !(isempty(cer_obj.object.rrdp_notify))
        (rrdp_host, _) = split_rrdp_path(cer_obj.object.rrdp_notify)
        if !(rrdp_host in keys(lookup.pubpoints))
            lookup.pubpoints[rrdp_host] = cer_node
        end
    end

    cer_node.remark_counts_me = count_remarks(cer_obj.tree)
    if tpi.stripTree
        cer_obj.tree = nothing
    end

    #TODO: should we still process through the directory, even though there was
    #no manifest?
    if !isfile(mft_fn)
        @error "manifest $(basename(mft_fn)) not found"
        add_missing_filename!(lookup, mft_fn, cer_node)
        remark_missingFile!(cer_obj, "Manifest file $(basename(mft_fn)) not in repo")
    else

        try
            mft = process_mft(mft_fn, lookup, tpi, cer_node)
            add(cer_node, mft)
        catch e
            if e isa LoopError
                @warn "Loop! between $(basename(e.file1)) and $(basename(e.file2))"
                #throw(e)
            else
                #showerror(stderr, e, catch_backtrace())
                #print(e)
                rethrow(e)
            end
        end

        # TODO check RFC on directory structures: do the .mft and .cer have to
        # reside in the same dir?

    end
    # we already counted the remarks from .tree, now add those from the object:
    cer_node.remark_counts_me += count_remarks(cer_obj)

    add_filename!(lookup, cer_fn, cer_node)
    #@debug "end of process_cer, popping rsaModulus, $(length(tpi.ca_rsaModulus)) left on stack"
    pop!(tpi.ca_rsaModulus)
    pop!(tpi.ca_rsaExponent)
    pop!(tpi.issuer)
    pop!(tpi.certStack)
    cer_node
end

function retrieve_all(tal_urls=TAL_URLS; stripTree::Bool=false, nicenames=true) :: Tuple{RPKINode, Lookup}
    lookup = Lookup()
    root = RPKINode()
    for (rir, rsync_url) in tal_urls
        (hostname, cer_fn) = split_scheme_uri(rsync_url)  
        rir_dir = joinpath(REPO_DIR, hostname)

        # For now, we rely on Routinator for the actual fetching
        # We do however construct all the paths and mimic the entire procedure
        if !isdir(rir_dir)
            @error "repo dir not found: $(rir_dir)"
            @assert isdir(rir_dir)
        end

        # 'rsync' the .cer from the TAL
        ta_cer = joinpath(rir_dir, cer_fn)
        @info "Processing $(rir)"
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
        
    end
    (root, lookup)
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

function _html(tree::RPKINode, io::IOStream)
    if !isnothing(tree.obj)
        if tree.obj isa String
            write(io, "<li><span class='caret'>$(tree.obj)")
        else
            html(tree.obj, "/tmp/jdrhtml")
            # a href to html_path(Object)
            write(io, "<li><span class='caret'>$(nameof(typeof(tree.obj).parameters[1]))")
            if tree.obj isa RPKIObject{CER}
                write(io, " [$(split_scheme_uri(tree.obj.object.pubpoint)[1])]")
            end
            write(io, " <a target='_blank' href='file://$(html_path(tree.obj, "/tmp/jdrhtml"))'>")
            write(io, "$(basename(tree.obj.filename))")
            write(io, "</a>")
        end
            write(io, " <span style='color:red'>$(count_remarks(tree))</span>")
            write(io, "</span>\n")
    else
        write(io, "<li><span class='caret'>unsure, tree.obj was nothing<span>\n")
    end
    if ! isempty(tree.children)
        write(io, "<ul class='nested'>\n")
        for c in tree.children
            _html(c, io) 
        end
        write(io, "</ul>\n")
    elseif tree.obj isa RPKIObject{ROA}
        write(io, "<ul class='nested'>\n")
        write(io, "<li class='roa'>$(tree.obj.object.asid)</li>")
        for r in tree.obj.object.vrps
            write(io, "<li class='roa'>$(r)</li>")
        end
        write(io, "</ul>\n")

    end
    write(io, "</li>\n")
end

function html(tree::RPKINode, output_fn::String) 
    STATIC_DIR = normpath(joinpath(pathof(parentmodule(RPKI)), "..", "..", "static"))
    open(output_fn, "w") do io
        write(io, "<link rel='stylesheet' href='file://$(STATIC_DIR)/style.css'/>\n")
        write(io, "<h1>JDR</h1>\n\n")
        write(io, "<ul id='main'>\n")
        write(io, "<li>root</li>\n")
        for c in tree.children
            _html(c, io)
        end
        write(io, "</ul>\n")
        write(io, "<!-- done -->\n")
        write(io, "<script type='text/javascript' src='file://$(STATIC_DIR)/javascript.js'></script>")
    end
    @debug "written $(output_fn)"
end


# this is to generate a separate .html file for RPKIObject{CER/MFT/ROA/CRL}
# NOT to be used in any recursive way in html(::RPKINode)
function html_path(o::RPKIObject, output_dir::String)
    normpath(joinpath(output_dir, replace(o.filename, REPO_DIR => ".", count=1)) * ".html")
end
function html(o::RPKIObject{CER}, output_dir::String)
    output_fn = html_path(o, output_dir)
    mkpath(dirname(output_fn))
    STATIC_DIR = normpath(joinpath(pathof(parentmodule(RPKI)), "..", "..", "static"))
    open(output_fn, "w") do io
        write(io, "<link rel='stylesheet' href='file://$(STATIC_DIR)/style.css'/>\n")
        write(io, "<h1>JDR</h1>\n")
        write(io, "<h2>Certificate: $(basename(o.filename))</h2>\n")
        write(io, "<b>pubpoint:</b> $(o.object.pubpoint)<br/>")
        write(io, "<b>manifest:</b> $(o.object.manifest)<br/>")
        write(io, "<b>rrdp:</b> $(o.object.rrdp_notify)<br/>")
        write(io, "<b>ASNs:</b> $(o.object.ASNs)<br/>")
        write(io, "<b>prefixes:</b> $(o.object.prefixes)<br/>")
        write(io, "<ul class='asn'>")
        ASN._html(o.tree, io)
        write(io, "</ul>")
    end
end
function html(o::RPKIObject{MFT}, output_dir::String)
    output_fn = html_path(o, output_dir)
    mkpath(dirname(output_fn))
    STATIC_DIR = normpath(joinpath(pathof(parentmodule(RPKI)), "..", "..", "static"))
    open(output_fn, "w") do io
        write(io, "<link rel='stylesheet' href='file://$(STATIC_DIR)/style.css'/>\n")
        write(io, "<h1>JDR</h1>\n")
        write(io, "<h2>Manifest: $(basename(o.filename))</h2>\n")
        write(io, "<b>listed files:</b> </br>")
        write(io, "<ul>")
        for f in o.object.files
            write(io, "<li>$(f)</li>")
        end
        write(io, "</ul>")

        write(io, "<ul class='asn'>")
        ASN._html(o.tree, io)
        write(io, "</ul>")
    end
end
function html(o::RPKIObject{ROA}, output_dir::String)
    output_fn = html_path(o, output_dir)
    mkpath(dirname(output_fn))
    STATIC_DIR = normpath(joinpath(pathof(parentmodule(RPKI)), "..", "..", "static"))
    open(output_fn, "w") do io
        write(io, "<link rel='stylesheet' href='file://$(STATIC_DIR)/style.css'/>\n")
        write(io, "<h1>JDR</h1>\n")
        write(io, "<h2>ROA: $(basename(o.filename))</h2>\n")
        write(io, "<b>ASID:</b> $(o.object.asid) </br>")
        write(io, "<b>Prefixes:</b> </br>")
        write(io, "<ul>")
        for v in o.object.vrps
            write(io, "<li>$(v.prefix) , maxLength: $(v.maxlength)</li>")
        end
        write(io, "</ul>")

        write(io, "<ul class='asn'>")
        ASN._html(o.tree, io)
        write(io, "</ul>")
    end
end

# Generate HTML for a 'Lookup query'
# this is temporary: ideally we make something XHR JSON based
# for now, this is only here to show what we can do with JDR
#
function search_asn_html(lookup::Lookup, asn::AutSysNum, output_dir::String)
    if ! (asn in keys(lookup.ASNs))
        @error "asn not in Lookup cache"
        return
    end

    output_fn = normpath(joinpath(output_dir, "$(asn.asn).html"))
    @debug output_fn
    mkpath(dirname(output_fn))
    STATIC_DIR = normpath(joinpath(pathof(parentmodule(RPKI)), "..", "..", "static"))

    open(output_fn, "w") do io
        numnodes = length(lookup.ASNs[asn])
        write(io, "<h2>", "$(numnodes)", " ROAs found for ", "AS$(asn.asn)", "</h2>")

        for roanode in lookup.ASNs[asn]
            write(io, "<div style='border: 1px solid black;'>")
            write(io, "<div>")
            write(io, "prefixes: ")
            write(io, "<ul>")
            for vrp in roanode.obj.object.vrps
                write(io, "<li>", "$(vrp.prefix)-$(vrp.maxlength)", "</li>")
            end
            write(io, "</ul>")
            write(io, "</div>")
            parent = roanode
            while !(isnothing(parent.obj))
                #write(io, "via ", parent.obj.filename, "<br/>")
                write(io, "&#x2193;<a href='$(html_path(parent.obj, output_dir))'>$(basename(parent.obj.filename))</a><br/>")
                parent = parent.parent
            end
            write(io, "</div><br/>")

        end
    end
end

end # module
