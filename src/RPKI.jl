module RPKI
using ..ASN
using ..DER
using IPNets


export retrieve_all

#abstract type RPKIObject <: AbstractNode end
struct RPKIObject{T}
    filename::String
    tree::Node
    object::T
end


function RPKIObject{T}(filename::String, tree::Node) where T 
    RPKIObject{T}(filename, tree, T())
end

include("RPKI/CER.jl")
include("RPKI/MFT.jl")
include("RPKI/ROA.jl")
include("RPKI/CRL.jl")

include("RPKI/validation_common.jl")


function RPKIObject(filename::String)::RPKIObject
    tree = DER.parse_file_recursive(filename)
    ext = lowercase(splitext(filename)[2])
    if      ext == ".cer" RPKIObject{CER}(filename, tree)
    elseif  ext == ".mft" RPKIObject{MFT}(filename, tree)
    elseif  ext == ".roa" RPKIObject{ROA}(filename, tree)
    end
end


mutable struct RPKINode
    parent::Union{Nothing, RPKINode}
    children::Vector{RPKINode}
    obj::Union{Nothing, RPKIObject, String}
end
function add(p::RPKINode, c::RPKINode)#, o::RPKIObject)
    c.parent = p
    #c.obj = o
    push!(p.children, c)
end
function add(p::RPKINode, c::Vector{RPKINode})
    #[child.parent = p for child in c]
    #Base.append!(p.children, c)
    for child in c
        add(p, child)
    end
end

function count_remarks(tree::RPKINode) :: Integer
    if isnothing(tree.obj)
        return 0
    end
    if tree.obj isa String # for the pubpoints tree
        return sum([count_remarks(c) for c in tree.children])
    end
    if isempty(tree.children)
        return ASN.count_remarks(tree.obj.tree)
    end
    #TODO should we actually go into .obj.tree? 
    return ASN.count_remarks(tree.obj.tree) + sum([count_remarks(c) for c in tree.children])
end

function check(::RPKIObject{T}) where {T}
    @warn "unknown RPKIObject type"
end


# Retrieving and validating the entire repository 

# start at the RIR TAs
TAL_URLS = Dict(
    :afrinic    => "rsync://rpki.afrinic.net/repository/AfriNIC.cer",
    :apnic      => "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
    :arin       => "rsync://rpki.arin.net/repository/arin-rpki-ta.cer",
    :lacnic     => "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer",
    :ripe       => "rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer"
)
REPO_DIR = joinpath(homedir(), ".rpki-cache/repository/rsync")

# TODO move to validation_common ?
function split_rsync_url(url::String) :: Tuple{String, String}
    m = match(r"rsync://([^/]+)/(.*)", url)
    (hostname, cer_fn) = m.captures
    (hostname, cer_fn)
end

function process_roa(roa_fn::String)
    o::RPKIObject{ROA} = check(RPKIObject(roa_fn))
end

function process_mft(mft_fn::String) :: RPKINode
    m::RPKIObject{MFT} = try 
        check(RPKIObject(mft_fn))
    catch e 
        #showerror(stderr, e, catch_backtrace())
        @error "MFT: error with $(mft_fn)"
        return RPKINode(nothing, [], nothing)
    end
    #@debug m.filename
    mft_dir = dirname(mft_fn)
    roas = Vector{RPKINode}() 
    for f in m.object.files
        # check for .cer
        ext = splitext(f)[2] 
        if ext == ".cer"
            subcer_fn = joinpath(mft_dir, f)
            @assert isfile(subcer_fn)
            try
                # TODO
                # can .cer and .roa files be in the same dir / on the same level
                # of a manifest? in other words, can we be sure that if we reach
                # this part of the `if ext ==`, there will be no other files to
                # check?
                cer = process_cer(subcer_fn)
                push!(roas, cer)
            catch e
                #showerror(stderr, e, catch_backtrace())
                throw("MFT->.cer: error with $(subcer_fn): \n $(e)")
            end
        elseif ext == ".roa"
            roa_fn = joinpath(mft_dir, f)
            try
                roa = process_roa(roa_fn)
                push!(roas, RPKINode(nothing, [], roa))
            catch e
                #showerror(stderr, e, catch_backtrace())
                throw("MFT->.roa: error with $(roa_fn): \n $(e)")
            end
        end

    end

    # returning:
    me = RPKINode(nothing, [], m)
    add(me, roas)
    #RPKINode(nothing, roas, m)
    me
end

TMP_UNIQ_PP = Set()
function process_cer(cer_fn::String) :: RPKINode
    #@debug cer_fn
    # now, for each .cer, get the CA Repo and 'sync' again
    o::RPKIObject{CER} = check(RPKIObject(cer_fn))
    #@debug o.object.pubpoint

    (ca_host, ca_path) = split_rsync_url(o.object.pubpoint)
    ca_dir = joinpath(REPO_DIR, ca_host, ca_path)
    push!(TMP_UNIQ_PP, ca_host)
    @assert isdir(ca_dir)

    mft_host, mft_path = split_rsync_url(o.object.manifest)
    mft_fn = joinpath(REPO_DIR, mft_host, mft_path)
    #@assert isfile(mft_fn)
    rpki_node = RPKINode(nothing, [], o)

    if !isfile(mft_fn)
        @error "manifest $(basename(mft_fn)) not found"
        return rpki_node
    end
    #@debug mft_fn
    #m = nothing
    
    try
        mft = process_mft(mft_fn)
        add(rpki_node, mft)
    catch e
        #nothing
        throw(e)
    end

    # TODO check RFC on directory structures: do the .mft and .cer have to
    # reside in the same dir?

    # ireturning:
    #rpki_node = RPKINode(nothing, [], o)
    #@debug "process_cer add() on", rpki_node, "\n", mft
    rpki_node
end

function retrieve_all()
    root = RPKINode(nothing, [], nothing)
    for (rir, rsync_url) in TAL_URLS
        @debug rir
        (hostname, cer_fn) = split_rsync_url(rsync_url)  
        rir_dir = joinpath(REPO_DIR, hostname)

        # For now, we rely on Routinator for the actual fetching
        # We do however construct all the paths and mimic the entire procedure
        @assert isdir(rir_dir)

        # 'rsync' the .cer from the TAL
        ta_cer = joinpath(rir_dir, cer_fn)
        @assert isfile(ta_cer)

        # start recursing
        try
            add(root, process_cer(ta_cer))
        catch e
            # TODO: what is a proper way to record the error, but continue with
            # the rest of the repo?
            # maybe a 'hard error counter' per RIR/pubpoint ?
            # also revisit the try/catches in process_cer()
            
            @error "error while processing $(ta_cer)"
            @error e

            #throw(e)
            
        end
        
    end
    @debug "TMP_UNIQ_PP length $(length(TMP_UNIQ_PP))"
    [@debug pp for pp in TMP_UNIQ_PP]
    root
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
                    @debug "new but duplicate: $(this_pp)"
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

end # module
