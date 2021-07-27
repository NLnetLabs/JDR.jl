module Webservice
using JDR.Config: CFG, generate_config
using JDR.RPKICommon: rsync, rrdp
using JDR.RPKI#: process_tas, link_resources!
using JDR.BGP: RISTree, ris_from_file, search
using JDR.Common: AutSysNum, AutSysNumRange, IPRange, RemarkCounts_t, Remark, RemarkLevel, RemarkType
using JDR.Common: split_scheme_uri

using HTTP#: Router, HTTP.Request, @register

using JSON3
using StructTypes

using Atlas

using Dates: Minute
using FileWatching
using ThreadPools
using Query

# for CleanLogger.jl:
using Logging: Logging
using LoggingExtras: MinLevelLogger, TeeLogger, TransformerLogger
using Dates: Dates, DateTime, now, UTC


using ReadWriteLocks
include("JSONHelpers.jl")
include("CleanLogger.jl")

const ROUTER = HTTP.Router()
const APIV = "/api/v1"

mutable struct State
    tree::RPKINode
    lookup::Lookup
    RISv6::RISTree{IPv6}
    RISv4::RISTree{IPv4}
    AtlasStatus::Dict
    last_update::DateTime
    last_update_serial::Int64
end

struct Metadata
    results_total::Int
    results_shown::Union{Nothing, Int}
end
Metadata(n::Int) = Metadata(n, nothing)

StructTypes.StructType(::Type{Metadata}) = StructTypes.Struct()
StructTypes.omitempties(::Type{Metadata}) = (:results_shown,)

const STATE = State(RPKINode(),
                    Lookup(),
                    RISTree{IPv6}(),
                    RISTree{IPv4}(),
                    Dict(),
                    now(UTC),
                    0
                   )

const WATCH_FN = "/tmp/rpkicache.updated"

const rwlock = ReadWriteLock()


##############################
# Endpoints
##############################

function asn(req::HTTP.Request)
    # /api/v1/asn/10, get 10
    asid = HTTP.URIs.splitpath(req.target)[4] 
    res = search(STATE.lookup, AutSysNum(asid))

    @info "ASN search on '$(asid)': $(length(res)) result(s)"
    if length(HTTP.URIs.splitpath(req.target)) > 4 && 
        HTTP.URIs.splitpath(req.target)[5]  == "raw"
        @info "RAW request"
        return [to_root(r) for r in res], Metadata(length(res))
    else
        return to_vue_tree(map(to_vue_branch, res)), Metadata(length(res))
    end
end

const PREFIX_RESULT_MAX = 20
function prefix(req::HTTP.Request)
    # /api/v1/prefix/1.2.3.4/24, get and unescape prefix
    parts = HTTP.URIs.splitpath(req.target)

    iprange = if length(parts) == 4
        # no prefixlen passed
        IPRange(parts[4])
    elseif length(parts) > 4
        _prefix = HTTP.URIs.splitpath(req.target)[4] 
        _prefixlen = HTTP.URIs.splitpath(req.target)[5] 
        IPRange(_prefix*'/'*_prefixlen)
    else
        throw("error: illegal prefix request")
    end

         
    include_more_specific = true
    res = search(STATE.lookup, iprange, include_more_specific)

    if length(res) > PREFIX_RESULT_MAX
        @warn "more than $(PREFIX_RESULT_MAX) results ($(length(res))) for /prefix search on '$(iprange)', limiting .."
        meta = Metadata(length(res), PREFIX_RESULT_MAX)
        res = Iterators.take(res, PREFIX_RESULT_MAX)
    else
        @info "prefix search on '$(iprange)': $(length(res)) result(s)"
        meta = Metadata(length(res))
    end

    if length(HTTP.URIs.splitpath(req.target)) > 5 && 
        HTTP.URIs.splitpath(req.target)[6]  == "raw"
        @info "RAW request"
        return [to_root(r) for r in res], meta
    else
        return to_vue_tree(map(to_vue_branch, res)), meta
    end
end

const FILENAME_RESULT_MAX = 20
function filename(req::HTTP.Request)
    # /api/v1/filename/somefilename, get and unescape filename
    filename = HTTP.URIs.splitpath(req.target)[4]
    filename = strip(HTTP.URIs.unescapeuri(filename))
    res = search(STATE.lookup, filename)
    if length(res) > FILENAME_RESULT_MAX
        @warn "more than $(FILENAME_RESULT_MAX) results ($(length(res))) for /filename search on '$(filename)', limiting .."
        meta = Metadata(length(res), FILENAME_RESULT_MAX)
        res = map(e->e.second, (Iterators.take(res, FILENAME_RESULT_MAX)))
    else
        @info "filename search on '$(filename)': $(length(res)) result(s)"
        meta = Metadata(length(res))
    end

    # because we can match on e.g. parts of a directory name, the results can
    # contain any object type. To get a proper vue tree, make sure we 'end' on
    # MFTs:
    # 1. get proper leaf nodes (if not a ROA, should be a MFT)
    # 2. remove any duplicates
    # 3. create the branches and the tree
    
    values(res) .|>
        get_vue_leaf_node |>
        unique .|>
        to_vue_branch |>
        to_vue_tree, meta
end

function object(req::HTTP.Request)
    # /api/v1/object/escaped_filename, get and unescape filename
    object = HTTP.URIs.splitpath(req.target)[4] 
    object = HTTP.URIs.unescapeuri(object)
    res = search(STATE.lookup, object)
    if isempty(res)
        @warn "no results, returning empty array"
        return [], Metadata(0)
    end
    if length(res) > 1
        @warn "more than 1 result for this query, unexpected"
    end
    
    ObjectDetails(first(res).second.obj, first(res).second.remark_counts_me), Metadata(length(res))
end

function pubpoints(::HTTP.Request)
    # /api/v1/pubpoints
    to_vue_pubpoints(STATE.tree), Metadata(1)
end

function ppstatus(::HTTP.Request)
    # /api/v1/ppstatus
    STATE.AtlasStatus, Metadata(1)
end

function uris(::HTTP.Request)
    STATE.lookup.pubpoints |>
    @map(_.second[2]) |> # get all Set(RPKINode)s
        @map(
             map(n->n.obj.object, collect(_)) # get the actual RPKIObject{CER}
            ) |>
        Iterators.flatten |>
        @map(
            Dict(:name => RPKICommon.split_scheme_uri(_.pubpoint)[1],
                 :rsync => _.pubpoint,
                 :rrdp => _.rrdp_notify) ) |>
        es -> unique(e->e[:name], es) |>
        collect, Metadata(1)
end

function repostats(::HTTP.Request)
    # /api/v1/repostats, 
    #repo = HTTP.URIs.splitpath(req.target)[4] 
    #repo = HTTP.URIs.unescapeuri(repo)
    @debug "repostats call"

    # for all the repositories (pubpoints)
    # get the remarks_per_repo
    # and map each remark to the detail URL of the RPKINode
    remarks = RPKICommon.remarks_per_repo(STATE.tree)
    res = keys(STATE.lookup.pubpoints) |>
    @map(Dict("repo" => _, "remarks" => 
                   map(p->
                       RemarkDeeplink(p.first, p.second.obj.filename),
                       get(remarks, _, [])
                      )
                  )
        ) |>
    collect

    #@filter(!isempty(_.second["remarks"])) |> # filter out repos with no remarks
    sort!(res, by=e->length(e["remarks"]), rev=true)

    res, Metadata(1)
end

function newsince(req::HTTP.Request)
    # /api/v1/newsince/timeperiod/filtertype
    splitted = HTTP.URIs.splitpath(req.target)
    timeperiod = Minute(60)
    if length(splitted) >= 4
        try 
            timeperiod = Minute(parse(Int, splitted[4]))
        catch
            @debug "invalid integer passed to /newsince, defaulting to $(timeperiod)"
        end
    end
    filtertype = if length(splitted) >= 5
        if uppercase(splitted[5]) == "CER"
            CER
        elseif uppercase(splitted[5]) == "MFT"
            MFT
        elseif uppercase(splitted[5]) == "CRL"
            CRL
        elseif uppercase(splitted[5]) == "ROA"
            ROA
        else
            CER
        end
    end
    res = new_since(STATE.tree, timeperiod) |>
        @filter(isnothing(filtertype) || _.obj.object isa filtertype) .|>
        get_vue_leaf_node |>
        unique

    res .|> to_vue_branch |> to_vue_tree , Metadata(length(res))
end

function bgp_prefix(req::HTTP.Request)
    prefix = HTTP.URIs.splitpath(req.target)[5] 
    prefix_len = HTTP.URIs.splitpath(req.target)[6] 
    include_more_specific = true
    ipr = try
        IPRange(prefix*'/'*prefix_len)
    catch
        @warn "bgp_prefix, invalid prefix: $(prefix)"
    end
    prefixes_found = if ipr.first isa IPv6
        search(STATE.RISv6, ipr, include_more_specific)
    else
        search(STATE.RISv4, ipr, include_more_specific)
    end
    prefixes_and_origins = map(e-> (string(IPRange(e.first, e.last)), e.value), unique(prefixes_found)) 

    # populate the result with all prefixes found in BGP
    res = Dict{Tuple{String,AutSysNum},Union{Nothing,Set{Dict}}}()
    for (p,o) in prefixes_and_origins
        res[(p,o)] = nothing
    end

    matches = if ipr.first isa IPv6
        intersect(STATE.lookup.resources_v6, prefixes_found) |> @filter(first(_).value.obj.object isa RPKI.ROA) |> unique |> collect
    else
        intersect(STATE.lookup.resources_v4, prefixes_found) |> @filter(first(_).value.obj.object isa RPKI.ROA) |> unique |> collect
    end
    for m in matches
        bgp_pfx = IPRange(m[2].first, m[2].last)
        roa = m[1].value.obj.object
        prefix = string(bgp_pfx)

        vrps = if bgp_pfx.first isa IPv6
            map(collect(intersect(roa.vrp_tree.resources_v6, (bgp_pfx.first, bgp_pfx.last)))) do e
                vrp_prefix = IPRange(e.first, e.last)
                vrp_bigger = length(vrp_prefix) > length(bgp_pfx)
                maxlen = e.value
                Dict(
                     "prefix" => string(vrp_prefix),
                     "maxlen" => maxlen,
                     "vrp_bigger" => vrp_bigger,
                     "maxlen_violated" => vrp_bigger && maxlen <= 128 - log2(length(bgp_pfx))
                   )
            end
        else
            map(collect(intersect(roa.vrp_tree.resources_v4, (bgp_pfx.first, bgp_pfx.last)))) do e
                vrp_prefix = IPRange(e.first, e.last)
                vrp_bigger = length(vrp_prefix) > length(bgp_pfx)
                maxlen = e.value
                Dict(
                     "prefix" => string(vrp_prefix),
                     "maxlen" => maxlen,
                     "vrp_bigger" => vrp_bigger,
                     "maxlen_violated" => vrp_bigger && maxlen < 32 - log2(length(bgp_pfx))
                   )
            end
        end

        origin = m[2].value
        if isnothing(res[(prefix, origin)])
            res[(prefix, origin)] = Set{Dict}()
        end
        push!(res[(prefix, origin)],  Dict(
                        "roa" => m[1].value.obj.filename,
                        "repo" => RPKICommon.get_pubpoint(m[1].value),
                        "vrps" => vrps,
                        "asid" => roa.asid,
                       )
             )

    end
    res2 = []
    for (k,v) in sort(res)
        (prefix, origin) = k
        push!(res2, 
              Dict("bgp" => prefix, "origin" => origin.asn, "matches" => v)
             )
    end

    res2, Metadata(length(res2))
end
function bgp(req::HTTP.Request)
    # /api/v1/bgp/asn
    asid = HTTP.URIs.splitpath(req.target)[4] 
    try
        asid = AutSysNum(asid)
    catch
        return [], Metadata(0)
    end


    risv4 = search(STATE.RISv4, asid)
    risv6 = search(STATE.RISv6, asid)
    prefixes = map(e-> string(IPRange(e.first, e.last)), risv4) |> unique
    prefixes6 = map(e-> string(IPRange(e.first, e.last)), risv6) |> unique

    # populate the result with all prefixes found in BGP
    res = Dict{Tuple{String, AutSysNum},Union{Nothing,Set{Dict}}}()
    for p in vcat(prefixes, prefixes6)
        res[(p, asid)] = nothing
    end

    matches4 = intersect(STATE.lookup.resources_v4, risv4) |> @filter(first(_).value.obj.object isa RPKI.ROA) |> unique |> collect
    matches6 = intersect(STATE.lookup.resources_v6, risv6) |> @filter(first(_).value.obj.object isa RPKI.ROA) |> unique |> collect

    for m in vcat(matches6, matches4)
        bgp_pfx = IPRange(m[2].first, m[2].last)
        roa = m[1].value.obj.object
        prefix = string(bgp_pfx)

        vrps = if bgp_pfx.first isa IPv6
            map(collect(intersect(roa.vrp_tree.resources_v6, (bgp_pfx.first, bgp_pfx.last)))) do e
                vrp_prefix = IPRange(e.first, e.last)
                vrp_bigger = length(vrp_prefix) > length(bgp_pfx)
                maxlen = e.value
                Dict(
                     "prefix" => string(vrp_prefix),
                     "maxlen" => maxlen,
                     "vrp_bigger" => vrp_bigger,
                     "maxlen_violated" => vrp_bigger && maxlen <= 128 - log2(length(bgp_pfx))
                   )
            end
        else
            map(collect(intersect(roa.vrp_tree.resources_v4, (bgp_pfx.first, bgp_pfx.last)))) do e
                vrp_prefix = IPRange(e.first, e.last)
                vrp_bigger = length(vrp_prefix) > length(bgp_pfx)
                maxlen = e.value
                Dict(
                     "prefix" => string(vrp_prefix),
                     "maxlen" => maxlen,
                     "vrp_bigger" => vrp_bigger,
                     "maxlen_violated" => vrp_bigger && maxlen < 32 - log2(length(bgp_pfx))
                   )
            end
        end
        if isnothing(res[(prefix, asid)])
            res[(prefix, asid)] = Set{Dict}()
        end
        push!(res[(prefix, asid)],  Dict(
                        "roa" => m[1].value.obj.filename,
                        "repo" => RPKICommon.get_pubpoint(m[1].value),
                        "vrps" => vrps,
                        "asid" => roa.asid,
                       )
             )

    end
    res2 = []
    for (k,v) in sort(res)
        (prefix, origin) = k
        push!(res2, 
              Dict("bgp" => prefix, "origin" => origin.asn, "matches" => v)
             )
    end

    res2, Metadata(length(res2))
end

##############################
# Background workers/helpers 
##############################


include("atlas.jl")

"""
Fetches the latest measurement results from RIPE Atlas, evaluates which
repositories have network level issues, and store the results in PPSTATUS[].

"""
function update_repostatus()
    global rwlock
    msms = fetch_measurements()
    @time df = fetch_results(msms) |> create_df
    df = join_msm_def(df, msms);

    new_atlas_status = ppstatus(df)
    lock!(write_lock(rwlock))
    STATE.AtlasStatus = new_atlas_status
    unlock!(write_lock(rwlock))
end

function update()
    global rwlock
    @info "update() on thread $(Threads.threadid())"

    @time (tree, lookup) = process_tas(CFG["rpki"]["tals"]; transport=rrdp, fetch_data=true, stripTree=true, nicenames=false)
    RPKI.link_resources!.(tree.children)

    new_RISv6 = new_RISv4 = nothing
    try
        new_RISv4 = ris_from_file(IPv4, "riswhoisdump.IPv4")
        new_RISv6 = ris_from_file(IPv6, "riswhoisdump.IPv6")
    catch
        @error "failed to parse RIS whois dumps"
    end

    lock!(write_lock(rwlock))
    STATE.tree = tree
    STATE.lookup = lookup
    if !isnothing(new_RISv6)
        STATE.RISv6 = new_RISv6
    end
    if !isnothing(new_RISv4)
        STATE.RISv4 = new_RISv4
    end
    set_last_update()
    unlock!(write_lock(rwlock))

    new_RISv6 = new_RISv4 = tree = lookup = nothing
    GC.gc()

    try
        @info "updating repository status based on RIPE Atlas measurements"
        update_repostatus()
    catch e
        @error "Something went wrong while trying to fetch RIPE Atlas measurements"
        @error e
    end

    @info "update() done, serial: $(STATE.last_update_serial)"
end
function update(req::HTTP.Request)
    update()
    ("msg" => "update done")
end

function _init()
    HTTP.@register(ROUTER, "GET", APIV*"/asn/*", asn)
    HTTP.@register(ROUTER, "GET", APIV*"/prefix/*", prefix)
    HTTP.@register(ROUTER, "GET", APIV*"/object/*", object)
    HTTP.@register(ROUTER, "GET", APIV*"/filename/*", filename)
    HTTP.@register(ROUTER, "GET", APIV*"/pp/", pubpoints)
    HTTP.@register(ROUTER, "GET", APIV*"/ppstatus/", ppstatus)
    HTTP.@register(ROUTER, "GET", APIV*"/repostats/", repostats)
    HTTP.@register(ROUTER, "GET", APIV*"/newsince/", newsince)
    HTTP.@register(ROUTER, "GET", APIV*"/newsince/*", newsince)

    HTTP.@register(ROUTER, "GET", APIV*"/bgp/*", bgp)
    HTTP.@register(ROUTER, "GET", APIV*"/bgp/asn/*", bgp) # TODO rename bgp to bgp_asn
    HTTP.@register(ROUTER, "GET", APIV*"/bgp/prefix/*/*", bgp_prefix)


    #HTTP.@register(ROUTER, "GET", APIV*"/generate_msm/", generate_msm)

    HTTP.@register(ROUTER, "GET", APIV*"/update", update)


    HTTP.@register(ROUTER, "GET", APIV*"/uris", uris)
end

struct Envelope
    last_update::DateTime
    serial::Integer
    timestamp::DateTime
    meta::Any
    data::Any
    error::Union{Nothing, Any}
end

Envelope(l, s, t, m, d) = Envelope(l, s, t, m, d, nothing)

StructTypes.StructType(::Type{Envelope}) = StructTypes.Struct()
StructTypes.omitempties(::Type{Envelope}) = (:error,)

function set_last_update()
    STATE.last_update = now(UTC)
    STATE.last_update_serial += 1
end

function JSONHandler(req::HTTP.Request)
    global rwlock

    _tstart = now()

    try
        # first check if there's any request body
        body = IOBuffer(HTTP.payload(req))
        meta = nothing
        lock!(read_lock(rwlock))
        if eof(body)
            # no request body
            res = HTTP.Handlers.handle(ROUTER, req)
            if res isa HTTP.Response # default 404 handler
                @warn "[$(now(UTC))] request to non-existing endpoint $(req.target)"
                return res
            else
                response_body, meta = res
            end
        else
            # there's a body, so pass it on to the handler we dispatch to
            response_body, meta = handle(ROUTER, req, JSON3.read(body))
        end

        # wrap the response in an envelope
        response = Envelope(STATE.last_update, STATE.last_update_serial, now(UTC), meta, response_body)
        time_needed = now() - _tstart
        #if time_needed > Dates.Millisecond(200)
        #    @debug "[$(now())] returning response, took long: $(time_needed)"
        #end
        @info "[$(_tstart)] [took $(time_needed)] request: $(req.target)"
        return HTTP.Response(200,
                             [("Content-Type" => "application/json")];
                             body=JSON3.write(response)
                            )
    catch e
        @error "[$(_tstart) something when wrong, showing stacktrace but continuing service"
        @error "req:", req
        showerror(stderr,e, catch_backtrace())
        response = Envelope(STATE.last_update, STATE.last_update_serial, now(UTC), nothing, nothing, string(e))
        return HTTP.Response(500,
                             [("Content-Type" => "application/json")];
                             body=JSON3.write(response)
                            )
    finally
        unlock!(read_lock(rwlock))
    end
end

function updater()
    @info "updater spawned on thread $(Threads.threadid())"
    update()
    while true
        # watch file, to be touched whenever the RPKI repo on disk is updated
        try 
            _ = watch_file(WATCH_FN)
            @info "[$(now())] updater(): sleep done, running update()"
            @time update()
            @info "[$(now())] updater(): update() done, going to sleep again"

            # Force GC and get back even more memory via malloc_trim
            GC.gc()
            ccall(:malloc_trim, Cvoid, (Cint,), 0)
        catch e
            if e isa IOError
                @error "updater() IOerror:", e
                @info "updater going to sleep for 10 seconds"
                sleep(10)
            else
                @error "updater(), not an IOerror", e
            end
        end
    end
end


serverhandle = nothing
using Sockets
function start()
    init_logger()
    @debug "Active configuration:", CFG
    Atlas.set_api_key(CFG["webservice"]["atlas_api_key"])
    global serverhandle
    _init()

    # first run before we let the updater() handle everything
    if !isfile(WATCH_FN)
        touch(WATCH_FN)
    end

    ThreadPools.@tspawnat 2 updater()

    @info "starting webservice on CPU 1 out of $(Threads.nthreads()) available"

    serverhandle = Sockets.listen(IPv6("::1"), CFG["webservice"]["port"])
    ThreadPools.@tspawnat 1 begin
        try
            HTTP.serve(JSONHandler, server=serverhandle)
        catch e
            @error "in start()", e
        end
    end
end

function stop()
    global serverhandle
    close(serverhandle)
end
function restart()
    stop()
    start()
end

end # module

