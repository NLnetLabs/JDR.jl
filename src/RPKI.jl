module RPKI
using ...JDR.Common
using ..ASN
using ..DER
using ..PrefixTrees

using IPNets
using Dates
using SHA

export retrieve_all, RPKIObject, CER, MFT, CRL, ROA
export TmpParseInfo
export print_ASN1
export AutSysNum, AutSysNumRange, AsIdsOrRanges, covered

#abstract type RPKIObject <: AbstractNode end
mutable struct RPKIObject{T}
    filename::String
    tree::Union{Nothing, Node}
    object::T
    remarks::Union{Nothing, Vector{Remark}}
    remarks_tree::Union{Nothing, Vector{Remark}}
end


function Base.show(io::IO, obj::RPKIObject{T}) where T
    print(io, "RPKIObject type: ", nameof(typeof(obj).parameters[1]), '\n')
    print(io, "filename: ", basename(obj.filename), '\n')
    print(io, obj.object)
end

function print_ASN1(o::RPKIObject{T}; max_lines=0) where T
    ASN.print_node(o.tree; traverse=true, max_lines)
end


function RPKIObject{T}(filename::String, tree::Node) where T 
    RPKIObject{T}(filename, tree, T(), nothing, nothing)
end

# TODO:
# - can (do we need to) we further optimize/parametrize RPKINode on .obj?
mutable struct RPKINode
    parent::Union{Nothing, RPKINode}
    children::Vector{RPKINode}
    obj::Union{Nothing, RPKIObject, String}
    # remark_counts_me could be a wrapper to the obj.remark_counts_me 
    remark_counts_me::RemarkCounts_t
    remark_counts_children::RemarkCounts_t
end

struct AutSysNum
    asn::UInt32
end
struct AutSysNumRange
    first::AutSysNum
    last::AutSysNum
end
const AsIdsOrRanges = Vector{Union{AutSysNum,AutSysNumRange}}

AutSysNumRange(f::Integer, l::Integer) = AutSysNumRange(AutSysNum(f), AutSysNum(l))
covered(a::AutSysNum, b::AutSysNum) = a.asn == b.asn
covered(a::AutSysNum, r::AutSysNumRange) = a >= r.first && a <= r.last
covered(r1::AutSysNumRange, r2::AutSysNumRange) = r1.first >= r2.first && r1.last <= r2.last
covered(r::AutSysNumRange, a::AutSysNum) = r.first == a.asn == r.last 

import Base.isless
isless(a::AutSysNum, b::AutSysNum) = a.asn < b.asn
Base.show(io::IO, a::AutSysNum) = print(io, "AS", a.asn)
Base.show(io::IO, r::AutSysNumRange) = print(io, "$(r.first)..$(r.last)")
function covered(a::Union{AutSysNum,AutSysNumRange}, aior::AsIdsOrRanges) 
    for aor in aior
        if covered(a, aor)
            return true
        end
    end
    false
end
function covered(aior_a::AsIdsOrRanges, aior_b::AsIdsOrRanges)
    for aor in aior_a
        if !(covered(aor, aior_b))
             return false
         end
    end

   true 
end

#function issubset(aior_a::AsIdsOrRanges, aior_b::AsIdsOrRanges)
#end


include("Lookup.jl")
mutable struct TmpParseInfo
    lookup::Lookup
    setNicenames::Bool
    stripTree::Bool
    subjectKeyIdentifier::Vector{UInt8}
    signerIdentifier::Vector{UInt8}
    eContent::Union{Nothing,ASN.Node}
    signedAttrs::Union{Nothing,ASN.Node}
    saHash::String

    caCert::Union{Nothing,ASN.Node}
    ca_rsaExponent::Vector{Integer} # stack
    ca_rsaModulus::Vector{BigInt} # stack
    issuer::Vector{String} # stack

    eeCert::Union{Nothing,ASN.Node}
    ee_rsaExponent::Union{Nothing,ASN.Node}
    ee_rsaModulus::Union{Nothing,ASN.Node}

    eeSig::Union{Nothing,ASN.Node}
    #certStack::Vector{RPKI.CER} # to replace all the other separate fields here
    certStack::Vector{Any} # TODO rearrange include/modules so we can actually use type RPKI.CER here
    certValid::Union{Nothing,Bool}

    # for ROA:
    afi::UInt32
end
TmpParseInfo(;lookup=Lookup(),nicenames::Bool=true,stripTree=false) = TmpParseInfo(lookup, nicenames, stripTree,
                                                    [],
                                                    [],
                                                    nothing,
                                                    nothing,
                                                    "",

                                                    nothing,
                                                    [],
                                                    [],
                                                    [],

                                                    nothing,
                                                    nothing,
                                                    nothing,
                                                    nothing,
                                                    [],
                                                    nothing,
                                                    0x0)


#export X509
include("X509.jl")
#export CMS
include("CMS.jl")

include("RPKI/CER.jl")
include("RPKI/MFT.jl")
include("RPKI/ROA.jl")
include("RPKI/CRL.jl")


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


# FIXME: check how we actually use RPKINode() throughout the codebase
RPKINode(p, c, o) = RPKINode(p, c, o, RemarkCounts(), RemarkCounts())

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

# TODO move to validation_common ?
function split_rsync_url(url::String) :: Tuple{String, String}
    m = match(r"rsync://([^/]+)/(.*)", url)
    (hostname, cer_fn) = m.captures
    (hostname, cer_fn)
end
function split_rrdp_path(url::String) :: Tuple{String, String}
    m = match(r"https://([^/]+)(/.*)", url)
    (hostname, cer_fn) = m.captures
    (hostname, cer_fn)
end


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
        lookup.prefix_tree[vrp.prefix] = roanode
        if ((vrp.prefix isa IPv4Net && vrp.prefix.netmask > 24)
            || (vrp.prefix isa IPv6Net && vrp.prefix.netmask > 48))
            push!(lookup.too_specific, roanode)
        end
    end
end

function process_roa(roa_fn::String, lookup::Lookup, tpi::TmpParseInfo) :: RPKINode
    o::RPKIObject{ROA} = check_ASN1(RPKIObject{ROA}(roa_fn), tpi)
    roa_node = RPKINode(nothing, [], o)
    if roa_fn in keys(lookup.filenames) 
        push!(lookup.filenames[roa_fn], roa_node)
    else
        lookup.filenames[roa_fn] = [roa_node]
    end

    roa_node.remark_counts_me = count_remarks(o) + count_remarks(o.tree)

    @assert !isnothing(tpi.caCert)
    @assert !isnothing(tpi.eeCert)
    check_cert(o, tpi)

    # optionally strip the tree to save memory
    if tpi.stripTree
        o.tree = nothing
    end
    roa_node
end

struct LoopError <: Exception 
    file1::String
    file2::String
end
LoopError(file1::String) = LoopError(file1, "")
Base.showerror(io::IO, e::LoopError) = print(io, "loop between ", e.file1, " and ", e.file2)

function process_mft(mft_fn::String, lookup::Lookup, tpi::TmpParseInfo) :: RPKINode
    #if mft_fn in keys(lookup.filenames)
    #    @warn "$(mft_fn) already seen, loop?"
    #    throw("possible loop in $(mft_fn)" )
    #end
    m::RPKIObject{MFT} = try 
        check_ASN1(RPKIObject{MFT}(mft_fn), tpi)
    catch e 
        showerror(stderr, e, catch_backtrace())
        @error "MFT: error with $(mft_fn)"
        return RPKINode(nothing, [], nothing)
    end
    mft_dir = dirname(mft_fn)
    listed_files = Vector{RPKINode}()
	crl_count = 0
    crl_node = nothing

    check_cert(m, tpi)

    me = RPKINode(nothing, [], m)
    me.remark_counts_me = count_remarks(m.tree)
    if tpi.stripTree
        m.tree = nothing 
    end

    for f in m.object.files
        # check for .cer
        if !isfile(joinpath(mft_dir, f))
            @error "Missing file: $(f)"
            add_missing_file(m.object, f)
            err!(m, "Files listed in manifest missing on file system")
            continue
        end
        ext = lowercase(f[end-3:end])
        if ext == ".cer"
            subcer_fn = joinpath(mft_dir, f)
            #@assert isfile(subcer_fn)
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

                    if isnothing(m.object.loops)
                        m.object.loops = [basename(subcer_fn)]
                    else
                        push!(m.object.loops, basename(subcer_fn))
                    end
                    err!(m, "Loop detected!")
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
                #roanode = RPKINode(nothing, [], roa)
                #push!(roas, RPKINode(nothing, [], roa))
                push!(listed_files, roanode)
                add_roa!(lookup, roanode)
            catch e
                #showerror(stderr, e, catch_backtrace())
                #throw("MFT->.roa: error with $(roa_fn): \n $(e)")
                rethrow(e)
            end
        end

    end

    # returning:
    me.remark_counts_me += count_remarks(m) 
    add(me, listed_files)
    if mft_fn in keys(lookup.filenames) 
        push!(lookup.filenames[mft_fn], me)
    else
        lookup.filenames[mft_fn] = [me]
    end
    me
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
        lookup.filenames[cer_fn] = [RPKINode(nothing, [], nothing)]
    end

    o::RPKIObject{CER} = check_ASN1(RPKIObject(cer_fn), tpi)
    push!(tpi.certStack, o.object)
    check_cert(o, tpi)
    check_resources(o, tpi)

    (ca_host, ca_path) = split_rsync_url(o.object.pubpoint)
    ca_dir = joinpath(REPO_DIR, ca_host, ca_path)
    
    mft_host, mft_path = split_rsync_url(o.object.manifest)
    mft_fn = joinpath(REPO_DIR, mft_host, mft_path)
    rpki_node = RPKINode(nothing, [], o)

    if tpi.certValid
        push!(lookup.valid_certs, rpki_node)
    else
        push!(lookup.invalid_certs, rpki_node)
    end
    tpi.certValid = nothing

    if !(ca_host in keys(lookup.pubpoints))
        lookup.pubpoints[ca_host] = rpki_node
    end
    if !(isempty(o.object.rrdp_notify))
        (rrdp_host, _) = split_rrdp_path(o.object.rrdp_notify)
        if !(rrdp_host in keys(lookup.pubpoints))
            lookup.pubpoints[rrdp_host] = rpki_node
        end
    end

    rpki_node.remark_counts_me = count_remarks(o) + count_remarks(o.tree)
    if tpi.stripTree
        o.tree = nothing
    end

    #TODO: should we still process through the directory, even though there was
    #no manifest?
    if !isfile(mft_fn)
        @error "manifest $(basename(mft_fn)) not found"
        err!(o, "Manifest file $(basename(mft_fn)) not in repo")
        #return rpki_node
    else

        try
            mft = process_mft(mft_fn, lookup, tpi)
            add(rpki_node, mft)
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

        # ireturning:
        #rpki_node = RPKINode(nothing, [], o)
        #@debug "process_cer add() on", rpki_node, "\n", mft

        lookup.filenames[cer_fn] = [rpki_node]
    end
    #@debug "end of process_cer, popping rsaModulus, $(length(tpi.ca_rsaModulus)) left on stack"
    pop!(tpi.ca_rsaModulus)
    pop!(tpi.ca_rsaExponent)
    pop!(tpi.issuer)
    pop!(tpi.certStack)
    rpki_node
end

function retrieve_all(tal_urls=TAL_URLS; stripTree::Bool=false, nicenames=true) :: Tuple{RPKINode, Lookup}
    lookup = Lookup()
    root = RPKINode(nothing, [], nothing)
    for (rir, rsync_url) in tal_urls
        (hostname, cer_fn) = split_rsync_url(rsync_url)  
        rir_dir = joinpath(REPO_DIR, hostname)

        # For now, we rely on Routinator for the actual fetching
        # We do however construct all the paths and mimic the entire procedure
        @assert isdir(rir_dir)

        # 'rsync' the .cer from the TAL
        ta_cer = joinpath(rir_dir, cer_fn)
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

#function flatten_to_pubpoints!(tree::RPKINode)
#    for c in tree.children
#        if c.obj isa RPKIObject{CER}
#            @assert length(c.children) > 0
#            flatten_to_pubpoints!(c)
#        elseif c.obj isa RPKIObject{MFT}
#            subtree = c
#            flatten_to_pubpoints!(c)
#            add(tree, c)
#            #c.parent = tree
#            #deleteat!(tree.children, findfirst(tree.children, c))
#            #for subc in c.children
#            #    flatten_to_pubpoints!(subc)
#            #end
#            #@assert length(c.children) > 0
#            #flatten_to_pubpoints(c)
#        elseif c.obj isa RPKIObject{ROA}
#            # leaf
#            add(tree, c)
#        end
#    end
#end

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
            this_pp = split_rsync_url(c.obj.object.pubpoint)[1]
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
            pp = split_rsync_url(c.obj.object.pubpoint)[1]
            subtree = RPKINode(nothing, [], pp)
            _pubpoints!(subtree, c, pp)
            add(pp_tree, subtree)
        end
    end
    pp_tree
end


function collect_remarks_from_asn1!(o::RPKIObject{T}, node::Node) where T
    if !isnothing(node.remarks)
        o.remarks_tree = node.remarks
        #Base.append!(o.remarks_tree, node.remarks)
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
                write(io, " [$(split_rsync_url(tree.obj.object.pubpoint)[1])]")
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
