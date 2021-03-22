module Webservice
using HTTP
using Dates
using JSON2
using Atlas

#using IPNets
using FileWatching
using ThreadPools
using Query

using JDR
using JDR.BGP
using JDR.Common
using JDR.RPKICommon
include("JSONHelpers.jl")
include("CleanLogger.jl")


const ROUTER = HTTP.Router()
const APIV = "/api/v1"
const LAST_UPDATE = Ref(now(UTC))
const LAST_UPDATE_SERIAL = Ref(0)
const TREE = Ref(RPKI.RPKINode())
const LOOKUP = Ref(RPKI.Lookup())
const RISv4 = Ref(BGP.RISTree{IPv4}())
const RISv6 = Ref(BGP.RISTree{IPv6}())

const WATCH_FN = "/tmp/rpkicache.updated"
const UPDATELK = ReentrantLock()


#mutable struct PPStatus
#    ping6::Union{Nothing, Atlas.StatusCheckResult}
#    ping4::Union{Nothing, Atlas.StatusCheckResult}
#end
#PPStatus() = PPStatus(nothing, nothing)

#const PPSTATUS = Ref(Dict{String}{PPStatus}())
const PPSTATUS = Ref{Dict}(Dict())
#const PP2Atlas = Ref(Dict{String}{Vector{NamedTuple}}())


##############################
# Endpoints
##############################

function asn(req::HTTP.Request)
    # /api/v1/asn/10, get 10
    asid = HTTP.URIs.splitpath(req.target)[4] 
    res = RPKI.search(LOOKUP[], RPKI.AutSysNum(asid))

    @info "ASN search on '$(asid)': $(length(res)) result(s)"
    if length(HTTP.URIs.splitpath(req.target)) > 4 && 
        HTTP.URIs.splitpath(req.target)[5]  == "raw"
        @info "RAW request"
        return [to_root(r) for r in res] 
    else
        return to_vue_tree(map(to_vue_branch, res))
    end
end

const PREFIX_RESULT_MAX = 20
function prefix(req::HTTP.Request)
    # /api/v1/prefix/1.2.3.4/24, get and unescape prefix
    parts = HTTP.URIs.splitpath(req.target)
    #prefix = if length(parts) == 4
    #    # no prefixlen passed
    #    IPNet(parts[4])
    #elseif length(parts) > 4
    #    _prefix = HTTP.URIs.splitpath(req.target)[4] 
    #    _prefixlen = HTTP.URIs.splitpath(req.target)[5] 
    #    IPNet(_prefix*'/'*_prefixlen)
    #else
    #    throw("error: illegal prefix request")
    #end

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
    #res = collect(RPKI.search(LOOKUP[], prefix))
    #res = RPKI.search(TREE[], iprange, include_more_specific)
    res = RPKI.search(LOOKUP[], iprange, include_more_specific)


    if length(res) > PREFIX_RESULT_MAX
        @warn "more than $(PREFIX_RESULT_MAX) results ($(length(res))) for /prefix search on '$(iprange)', limiting .."
        res = Iterators.take(res, PREFIX_RESULT_MAX)
    else
        @info "prefix search on '$(iprange)': $(length(res)) result(s)"
    end

    if length(HTTP.URIs.splitpath(req.target)) > 5 && 
        HTTP.URIs.splitpath(req.target)[6]  == "raw"
        @info "RAW request"
        return [to_root(r) for r in res]
    else
        return to_vue_tree(map(to_vue_branch, res))
    end
end

const FILENAME_RESULT_MAX = 20
function filename(req::HTTP.Request)
    # /api/v1/filename/somefilename, get and unescape filename
    filename = HTTP.URIs.splitpath(req.target)[4]
    filename = strip(HTTP.URIs.unescapeuri(filename))
    res = RPKI.search(LOOKUP[], filename)
    if length(res) > FILENAME_RESULT_MAX
        @warn "more than $(FILENAME_RESULT_MAX) results ($(length(res))) for /filename search on '$(filename)', limiting .."
        res = map(e->e.second, (Iterators.take(res, FILENAME_RESULT_MAX)))
    else
        @info "filename search on '$(filename)': $(length(res)) result(s)"
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
        to_vue_tree
end

function object(req::HTTP.Request)
    # /api/v1/object/escaped_filename, get and unescape filename
    object = HTTP.URIs.splitpath(req.target)[4] 
    object = HTTP.URIs.unescapeuri(object)
    res = RPKI.search(LOOKUP[], object)
    if isempty(res)
        @warn "no results, returning empty array"
        return []
    end
    if length(res) > 1
        @warn "more than 1 result for this query, unexpected"
    end
    
    ObjectDetails(first(res).second.obj, first(res).second.remark_counts_me)
end

function pubpoints(req::HTTP.Request)
    # /api/v1/pubpoints
    to_vue_pubpoints(TREE[])
end

function ppstatus(req::HTTP.Request)
    # /api/v1/ppstatus
    PPSTATUS[]
end

function uris(req::HTTP.Request)
    LOOKUP[].pubpoints |>
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
        collect
end

function repostats(req::HTTP.Request)
    # /api/v1/repostats, 
    #repo = HTTP.URIs.splitpath(req.target)[4] 
    #repo = HTTP.URIs.unescapeuri(repo)
    @debug "repostats call"

    # for all the repositories (pubpoints)
    # get the remarks_per_repo
    # and map each remark to the detail URL of the RPKINode
    remarks = RPKICommon.remarks_per_repo(TREE[])
    res = keys(LOOKUP[].pubpoints) |>
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

    res
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
            RPKI.CER
        elseif uppercase(splitted[5]) == "MFT"
            RPKI.MFT
        elseif uppercase(splitted[5]) == "CRL"
            RPKI.CRL
        else
            RPKI.CER
        end
    end
    RPKI.new_since(TREE[], timeperiod) |>
        @filter(isnothing(filtertype) || _.obj.object isa filtertype) .|>
        get_vue_leaf_node |>
        unique .|>
        to_vue_branch |>
        to_vue_tree
end

function bgp(req::HTTP.Request)
    # /api/v1/bgp/asn
    asid = HTTP.URIs.splitpath(req.target)[4] 
    try
        asid = RPKI.AutSysNum(asid)
    catch
        return []
    end


    risv4 = JDR.BGP.search(RISv4[], asid)
    risv6 = JDR.BGP.search(RISv6[], asid)
    prefixes = map(e-> string(IPRange(e.first, e.last)), risv4) |> unique
    prefixes6 = map(e-> string(IPRange(e.first, e.last)), risv6) |> unique

    # populate the result with all prefixes found in BGP
    res = Dict{String,Union{Nothing,Set{Dict}}}()
    for p in vcat(prefixes, prefixes6)
        res[p] = nothing
    end

    matches4 = intersect(LOOKUP[].resources_v4, risv4) |> @filter(first(_).value.obj.object isa JDR.RPKI.ROA) |> unique |> collect
    matches6 = intersect(LOOKUP[].resources_v6, risv6) |> @filter(first(_).value.obj.object isa JDR.RPKI.ROA) |> unique |> collect

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
        if isnothing(res[prefix])
            res[prefix] = Set{Dict}()
        end
        push!(res[prefix],  Dict(
                        "roa" => m[1].value.obj.filename,
                        "repo" => JDR.RPKICommon.get_pubpoint(m[1].value),
                        "vrps" => vrps,
                        "asid" => roa.asid,
                       )
             )

    end
    res2 = []
    for (k,v) in sort(res)
        push!(res2, 
              Dict("bgp" => k, "matches" => v)
             )
    end

    res2
end


#= # not needed anymore because the NCC takes care of the measurements now
function _generate_msm_definitions(cer::RPKI.CER; params...) #:: Vector{Atlas.Definition}
    definitions = Vector()
    host_rsync, _ = split_scheme_uri(cer.pubpoint)
    common_params = Dict(
                         :resolve_on_probe => true,
                         :skip_dns_check => true,
                         :tags => ["jdr"],
                         :interval => 900,
                        )
    push!(definitions, Ping6(host_rsync; common_params..., params...))
    push!(definitions, Ping4(host_rsync; common_params..., params...))

    if !isempty(cer.rrdp_notify)
        rrdp_host, rrdp_path = split_rrdp_path(cer.rrdp_notify)
        if rrdp_host != host_rsync
            push!(definitions, Ping6(rrdp_host; common_params..., params...))
            push!(definitions, Ping4(rrdp_host; common_params..., params...))
        end
        # RIPE Atlas only allows HTTP measurements towards Atlas Anchors..
        # push!(definitions, HTTP6(cer.obj.object.rrdp_notify))
        # push!(definitions, HTTP4(cer.obj.object.rrdp_notify))
    end
    definitions
end
function _probe_selection() 
    Atlas.Probes(
                         tags=
                         Atlas.ProbeTags(
                                         include=["datacentre",
                                                  "native-ipv6",
                                                  "native-ipv4"],
                                         exclude=[]
                                        )
                        )
end

# generate_msm() is a helper to create a HTTP POST curl (or equivalent) call, to
# make measurements for all pubpoints currently in the RPKI repository
# wget http://localhost:8081/api/v1/generate_msm -O- | jq '.["data"]' > atlas_new_measurement.json
# noglob curl --dump-header - -H "Content-Type: application/json" -H "Accept: application/json" -X POST -d @atlas_new_measurement.json \
#  https://atlas.ripe.net/api/v2/measurements//?key=YOUR_ATLAS_API_KEY
function generate_msm(req::HTTP.Request)
    @info "generate_msm()"

    new_msm = Atlas.CreateMeasurement()
    for cer in values(LOOKUP[].pubpoints)
        for def in _generate_msm_definitions(cer.obj.object)
            Atlas.add_definition(new_msm, def)
        end
    end

    Atlas.add_probes(new_msm, _probe_selection())
    new_msm
end

=#

#= # RIPE NCC is doing everything for us now
function DEPRget_current_msm() :: Atlas.Measurement
    # fetch based on tag 'jdr'
    # determine and return group id
    current = Atlas.get_my(Dict("tags" => "jdr", "page_size" => "200"))
    # there should only be one active group_id for this tag:
    @debug "pre assert in get_current_msm"
    @assert length(unique([r.group_id for r in current.results])) == 1
    @debug "post assert"
    Atlas.Measurement(current.results[1].group_id)
end
=#
#= # TODO: extract the check to see if we are missing things
function renew_msm()
    # determine missing pp from current msm
    # setdiff returns what is in the first argument but not in the second
    # (thus we do not yield pubpoints that are in PP2Atlas but not in LOOKUP)
    get_atlas_info()
    missing_pps = setdiff(Set(keys(LOOKUP[].pubpoints)), Set(keys(PP2Atlas[])))
    @debug "in LOOKUP:"
    @debug keys(LOOKUP[].pubpoints)
    @debug "in PP2Atlas:"
    @debug keys(PP2Atlas[])

    current_msm = get_current_msm()
    @debug "current msm: $(current_msm.id)"
    if !isempty(missing_pps)
        @info "new pubpoints: $(missing_pps)"
        # create one api call to add new ping6/ping4 for all these pubpoints
        # use the existing group_id
        new_msm = Atlas.CreateMeasurement()
        probes = Probes(; type = "msm", value=current_msm.id)
        add_probes(new_msm, probes)
        _params = Dict(
                       :group_id=>current_msm.id,
                       :resolve_on_probe => true,
                       :skip_dns_check => true,
                       :tags => ["jdr"],
                       :interval => 900,
                      )
        for new_pp in missing_pps
            Atlas.add_definition(new_msm, Atlas.Ping6(new_pp; _params...))
            Atlas.add_definition(new_msm, Atlas.Ping4(new_pp; _params...))
        end
        @debug new_msm
        # and now POST to the Atlas API:
        Atlas.start_measurement(new_msm)
    else
        @info "got measurements for all pubpoints"
    end
    # add those, using group_id from get_current_msm
    # delete missing?

    missing_pps
end

=#


##############################
# Background workers/helpers 
##############################


include("atlas.jl")

"""
Fetches the latest measurement results from RIPE Atlas, evaluates which
repositories have network level issues, and store the results in PPSTATUS[].

"""
function update_repostatus()
    msms = fetch_measurements()
    @time df = fetch_results(msms) |> create_df
    df = join_msm_def(df, msms);

    PPSTATUS[] = ppstatus(df)
end


#=
function status_check()
    @debug "status_check(), length of PP2Atlas[] = $(length(PP2Atlas[]))"
    for pp in keys(LOOKUP[].pubpoints)
        if ! (pp in keys(PP2Atlas[]))
            @error "$(pp) in Lookup but not in Atlas measurements"
            continue
        end
        PPSTATUS[][pp] = PPStatus()
        for msm in PP2Atlas[][pp]
            try
                @debug "updating PPSTATUS for $(pp) based on $(msm.id)"
                status = Atlas.get_statuscheck(Atlas.Measurement(msm.id), pta=3)
                setproperty!(PPSTATUS[][pp], Symbol(msm.type, msm.af), status)
            catch e
                @error e
            end
        end

    end
    @info "end of status_check"
end
=#

function update()
    @info "update() on thread $(Threads.threadid())"
    @info "resetting Common.remarkTID"
    Common.resetRemarkTID()
    @assert Common.remarkTID == 0

    @time (tree, lookup) = RPKI.retrieve_all(JDR.CFG["rpki"]["tals"]; stripTree=true, nicenames=false)
    RPKI.link_resources!.(tree.children)

    try
        RISv4[] = JDR.BGP.ris_from_file(IPv4, "riswhoisdump.IPv4")
        RISv6[] = JDR.BGP.ris_from_file(IPv6, "riswhoisdump.IPv6")
    catch
        @error "failed to parse RIS whois dumps"
    end
    @debug "linked!"
    lock(UPDATELK)
    TREE[] = tree
    LOOKUP[] = lookup
    unlock(UPDATELK)

    try
        #= OLD remove
        #@info "skipping renew_msm(), using rpki-repositories-bundle msm"
        #@info "update() calling renew_msm()"
        #renew_msm()
        #get_atlas_info()
        #@info "update() calling status_check()"
        #status_check()
        =#
        
        # TMP commented out for dev
        @info "updating repository status based on RIPE Atlas measurements"
        update_repostatus()
    catch e
        @error "Something went wrong while trying to fetch RIPE Atlas measurements"
        @error e
    end

    set_last_update()
    @info "update() done, serial: $(LAST_UPDATE_SERIAL[])"
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


    #HTTP.@register(ROUTER, "GET", APIV*"/generate_msm/", generate_msm)

    HTTP.@register(ROUTER, "GET", APIV*"/update", update)


    HTTP.@register(ROUTER, "GET", APIV*"/uris", uris)
end

struct Envelope
    last_update::DateTime
    serial::Integer
    timestamp::DateTime
    data::Any
    error::Union{Nothing, Any}
end

Envelope(l, s, t, d) = Envelope(l, s, t, d, nothing)

JSON2.@format Envelope begin
    error => (omitempty=true,)
end

function set_last_update()
    LAST_UPDATE[] = now(UTC)
    LAST_UPDATE_SERIAL[] += 1
end

function JSONHandler(req::HTTP.Request)
    _tstart = now()

    try
        # first check if there's any request body
        body = IOBuffer(HTTP.payload(req))
        lock(UPDATELK)
        if eof(body)
            # no request body
            response_body = HTTP.Handlers.handle(ROUTER, req)
        else
            # there's a body, so pass it on to the handler we dispatch to
            response_body = handle(ROUTER, req, JSON2.read(body))
        end
        unlock(UPDATELK)

        # wrap the response in an envelope
        response = Envelope(LAST_UPDATE[], LAST_UPDATE_SERIAL[], now(UTC), response_body)
        time_needed = now() - _tstart
        #if time_needed > Dates.Millisecond(200)
        #    @debug "[$(now())] returning response, took long: $(time_needed)"
        #end
        @info "[$(_tstart)] [took $(time_needed)] request: $(req.target)"
        return HTTP.Response(200,
                             [("Content-Type" => "application/json")];
                             body=JSON2.write(response)
                            )
    catch e
        @error "[$(_tstart) something when wrong, showing stacktrace but continuing service"
        @error "req:", req
        showerror(stderr,e, catch_backtrace())
        response = Envelope(LAST_UPDATE[], LAST_UPDATE_SERIAL[], now(UTC), nothing, e)
        return HTTP.Response(500,
                             [("Content-Type" => "application/json")];
                             body=JSON2.write(response)
                            )
    finally
        if islocked(UPDATELK) && UPDATELK.locked_by === current_task()
            @debug "in JSONHandler finally clause: unlocking UPDATELK"
            unlock(UPDATELK)
        end
    end
end

function updater()
    @info "updater spawned on thread $(Threads.threadid())"
    while true
        # watch file, to be touched whenever the RPKI repo on disk is updated
        try 
            _ = watch_file(WATCH_FN)
            @info "[$(now())] updater(): sleep done, running update()"
            @time update()
            @info "[$(now())] updater(): update() done, going to sleep again"
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

#=
function DEPR_get_atlas_info()
    pp2atlas = Dict{String}{Vector{NamedTuple}}()
    #TODO: hardcoding page_size is not nice
    #jdr_tagged = Atlas.get_my(Dict("tags" => "jdr", "page_size" => "200"))
    msms = Atlas.get_measurement(Dict("tags" => "rpki-repositories-bundle", "page_size" => "500"))
    if length(unique([r.group_id for r in msms.results])) == 0 
        @error "no Atlas group measurement found for JDR"
        return
    elseif length(unique([r.group_id for r in msms.results])) > 1
        @warn "got more than one group id for JDR tagged Atlas measurements"
    end
    @info "got $(length(msms.results)) measurements tagged 'jdr' from Atlas"
    group_id = msms.results[1].group_id
    for r in msms.results
        if !(r.target in keys(pp2atlas))
            pp2atlas[r.target] = [r]
        else
            push!(pp2atlas[r.target], r)
        end

    end
    return PP2Atlas[] = pp2atlas
end
=#

serverhandle = nothing
using Sockets
function start()
    JDR.Config.generate_config()
    init_logger()
    @debug "Active configuration:", JDR.CFG
    Atlas.set_api_key(JDR.CFG["webservice"]["atlas_api_key"])
    global serverhandle
    _init()

    # first run before we let the updater() handle everything
    if !isfile(WATCH_FN)
        touch(WATCH_FN)
    end
    update()

    ThreadPools.@tspawnat 2 updater()

    @info "starting webservice on CPU 1 out of $(Threads.nthreads()) available"

    serverhandle = Sockets.listen(IPv6("::1"), JDR.CFG["webservice"]["port"])
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

