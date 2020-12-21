module Webservice
using HTTP
using Dates
using JSON2
using Atlas

using IPNets
using FileWatching
using ThreadPools
using Query

using JDR
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

const WATCH_FN = "/tmp/rpkicache.updated"
const UPDATELK = ReentrantLock()

const ATLAS_BILL_TO = "ripe@luukhendriks.eu"

mutable struct PPStatus
    ping6::Union{Nothing, Atlas.StatusCheckResult}
    ping4::Union{Nothing, Atlas.StatusCheckResult}
end
PPStatus() = PPStatus(nothing, nothing)

const PPSTATUS = Ref(Dict{String}{PPStatus}())
const PP2Atlas = Ref(Dict{String}{Vector{NamedTuple}}())


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
    prefix = if length(parts) == 4
        # no prefixlen passed
        IPNet(parts[4])
    elseif length(parts) > 4
        _prefix = HTTP.URIs.splitpath(req.target)[4] 
        _prefixlen = HTTP.URIs.splitpath(req.target)[5] 
        IPNet(_prefix*'/'*_prefixlen)
    else
        throw("error: illegal prefix request")
    end
         
    res = collect(RPKI.search(LOOKUP[], prefix))
    if length(res) > PREFIX_RESULT_MAX
        @warn "more than $(PREFIX_RESULT_MAX) results ($(length(res))) for /prefix search on '$(prefix)', limiting .."
        res = Iterators.take(res, PREFIX_RESULT_MAX)
    else
        @info "prefix search on '$(prefix)': $(length(res)) result(s)"
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
    filename = HTTP.URIs.unescapeuri(filename)
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
    @info "Object call for '$(object)': $(length(res)) result(s)"
    if isempty(res)
        @warn "no results, returning empty array"
        return []
    end
    @info "returning $(first(res).second.obj.filename)"
    
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
    @map(_ => Dict("remarks" => 
                   map(p->
                       RemarkDeeplink(p.first, JSONHelpers.details_url(p.second.obj.filename)),
                       get(remarks, _, [])
                      )
                  )
        ) |>
    collect

    #@filter(!isempty(_.second["remarks"])) |> # filter out repos with no remarks
    sort!(res, by=e->length(e.second["remarks"]), rev=true)

    res
end


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

function get_current_msm() :: Atlas.Measurement
    # fetch based on tag 'jdr'
    # determine and return group id
    current = Atlas.get_my(Dict("tags" => "jdr", "page_size" => "200"))
    # there should only be one active group_id for this tag:
    @debug "pre assert in get_current_msm"
    @assert length(unique([r.group_id for r in current.results])) == 1
    @debug "post assert"
    Atlas.Measurement(current.results[1].group_id)
end
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


##############################
# Background workers/helpers 
##############################

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

function update()
    @info "update() on thread $(Threads.threadid())"
    @info "resetting Common.remarkTID"
    Common.resetRemarkTID()
    @assert Common.remarkTID == 0

    @time (tree, lookup) = RPKI.retrieve_all(JDR.CFG["rpki"]["tals"]; stripTree=true, nicenames=false)
    RPKI.link_resources!.(tree.children)
    @debug "linked!"
    lock(UPDATELK)
    TREE[] = tree
    LOOKUP[] = lookup
    unlock(UPDATELK)

    try
        @info "update() calling renew_msm()"
        renew_msm()
        @info "update() calling status_check()"
        status_check()
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
    HTTP.@register(ROUTER, "GET", APIV*"/generate_msm/", generate_msm)

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
    @info "[$(_tstart)] request: $(req.target)"

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
        @info "[$(now())] returning response, took $(now() - _tstart)"
        return HTTP.Response(200,
                             [("Content-Type" => "application/json")];
                             body=JSON2.write(response)
                            )
    catch e
        @error "something when wrong, showing stacktrace but continuing service"
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

function get_atlas_info()
    pp2atlas = Dict{String}{Vector{NamedTuple}}()
    #TODO: hardcoding page_size is not nice
    jdr_tagged = Atlas.get_my(Dict("tags" => "jdr", "page_size" => "200"))
    if length(unique([r.group_id for r in jdr_tagged.results])) == 0 
        @error "no Atlas group measurement found for JDR"
        return
    elseif length(unique([r.group_id for r in jdr_tagged.results])) > 1
        @warn "got more than one group id for JDR tagged Atlas measurements"
    end
    @info "got $(length(jdr_tagged.results)) measurements tagged 'jdr' from Atlas"
    group_id = jdr_tagged.results[1].group_id
    for r in jdr_tagged.results
        if !(r.target in keys(pp2atlas))
            pp2atlas[r.target] = [r]
        else
            push!(pp2atlas[r.target], r)
        end

    end
    return PP2Atlas[] = pp2atlas
end

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

