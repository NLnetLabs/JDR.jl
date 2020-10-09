module Webservice
using HTTP
using Dates
using JSON2
using Atlas

using IPNets

using JDR
using JDR.Common
using JDR.RPKICommon
using JDR.JSONHelpers

const ROUTER = HTTP.Router()
const APIV = "/api/v1"
const LAST_UPDATE = Ref(now(UTC))
const LAST_UPDATE_SERIAL = Ref(0)
const TREE = Ref(RPKI.RPKINode())
const LOOKUP = Ref(RPKI.Lookup())

const ATLAS_BILL_TO = "ripe@luukhendriks.eu"

mutable struct PPStatus
    ping6::Union{Nothing, Atlas.StatusCheckResult}
    ping4::Union{Nothing, Atlas.StatusCheckResult}
end
PPStatus() = PPStatus(nothing, nothing)

const PPSTATUS = Ref(Dict{String}{PPStatus}())
const PP2Atlas = Ref(Dict{String}{Vector{NamedTuple}}())


const TAL_URLS = Dict(
    :afrinic    => "rsync://rpki.afrinic.net/repository/AfriNIC.cer",
    :apnic      => "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
    :arin       => "rsync://rpki.arin.net/repository/arin-rpki-ta.cer",
    :lacnic     => "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer",
    :ripe       => "rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer",
    :ripetest   => "rsync://localcert.ripe.net/ta/RIPE-NCC-TA-TEST.cer",
    :apnictest  => "rsync://rpki-testbed.apnic.net/repository/apnic-rpki-root-iana-origin-test.cer"
)


##############################
# Endpoints
##############################

function asn(req::HTTP.Request)
    # /api/v1/asn/10, get 10
    asid = HTTP.URIs.splitpath(req.target)[4] 
    res = RPKI.search(LOOKUP[], RPKI.AutSysNum(parse(UInt32, asid)))

    if length(HTTP.URIs.splitpath(req.target)) > 4 && 
        HTTP.URIs.splitpath(req.target)[5]  == "raw"
        @info "RAW request"
        return [to_root(r) for r in res] 
    else
        @info "returning new vue tree format"
        return to_vue_tree(map(to_vue_branch, res))
    end
end

function prefix(req::HTTP.Request)
    # /api/v1/prefix/1.2.3.4%2F24, get and unescape prefix
    prefix = HTTP.URIs.splitpath(req.target)[4] 
    prefix = HTTP.URIs.unescapeuri(prefix)
    prefix = IPNet(prefix)
    res = RPKI.search(LOOKUP[], prefix)

    if length(HTTP.URIs.splitpath(req.target)) > 4 && 
        HTTP.URIs.splitpath(req.target)[5]  == "raw"
        @info "RAW request"
        return [to_root(r) for r in res]
    else
        @info "returning new vue tree format"
        return to_vue_tree(map(to_vue_branch, res))
    end
end

function object(req::HTTP.Request)
    # /api/v1/object/escaped_filename, get and unescape filename
    object = HTTP.URIs.splitpath(req.target)[4] 
    object = HTTP.URIs.unescapeuri(object)
	@debug "object details call for $(object)"
    res = RPKI.search(LOOKUP[], object)
	@debug typeof(res)
	@debug length(res)
    
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



function _generate_msm_definitions(cer::RPKI.CER; params...) #:: Vector{Atlas.Definition}
    definitions = Vector()
    host_rsync, _ = RPKI.split_rsync_url(cer.pubpoint)
    push!(definitions, Ping6(host_rsync; skip_dns_check=true, tags=["jdr"], params...))
    push!(definitions, Ping4(host_rsync; skip_dns_check=true, tags=["jdr"], params...))

    if !isempty(cer.rrdp_notify)
        rrdp_host, rrdp_path = RPKI.split_rrdp_path(cer.rrdp_notify)
        if rrdp_host != host_rsync
            push!(definitions, Ping6(rrdp_host; skip_dns_check=true, tags=["jdr"], params...))
            push!(definitions, Ping4(rrdp_host; skip_dns_check=true, tags=["jdr"], params...))
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
# noglob curl --dump-header - -H "Content-Type: application/json" -H "Accept: application/json" -X POST -d @ atlas_new_measurement.json \
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
        for new_pp in missing_pps
            Atlas.add_definition(new_msm, Atlas.Ping6(new_pp))
            Atlas.add_definition(new_msm, Atlas.Ping4(new_pp))
        end
        Atlas.add_probes(new_msm, _probe_selection())
        @debug new_msm
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
        @debug "for pp $(pp)"
        if ! (pp in keys(PP2Atlas[]))
            @error "$(pp) in Lookup but not in Atlas measurements"
            continue
        end
        PPSTATUS[][pp] = PPStatus()
        for msm in PP2Atlas[][pp]
            @debug "updating PPSTATUS for $(pp) based on $(msm.id)"
            status = Atlas.get_statuscheck(Atlas.Measurement(msm.id))
            setproperty!(PPSTATUS[][pp], Symbol(msm.type, msm.af), status)
        end

    end
    @info "end of status_check"
end

function update()
    @info "update()"
    @info "resetting Common.remarkTID"
    Common.resetRemarkTID()
    @assert Common.remarkTID == 0

    (tree, lookup) = fetch(Threads.@spawn(RPKI.retrieve_all(TAL_URLS)))
    #(tree, lookup) = RPKI.retrieve_all(TAL_URLS)
    TREE[] = tree
    LOOKUP[] = lookup
    @info "update() calling renew_msm()"
    renew_msm()
    @info "update() calling status_check()"
    status_check()
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
    HTTP.@register(ROUTER, "GET", APIV*"/pp/", pubpoints)
    HTTP.@register(ROUTER, "GET", APIV*"/ppstatus/", ppstatus)
    HTTP.@register(ROUTER, "GET", APIV*"/generate_msm/", generate_msm)

    HTTP.@register(ROUTER, "GET", APIV*"/update", update)
end

struct Envelope
    last_update::DateTime
    serial::Integer
    timestamp::DateTime
    data::Any
end

function set_last_update()
    LAST_UPDATE[] = now(UTC)
    LAST_UPDATE_SERIAL[] += 1
end

function JSONHandler(req::HTTP.Request)
    @info "Request: $(req.target)"

    # first check if there's any request body
    body = IOBuffer(HTTP.payload(req))
    if eof(body)
        # no request body
        response_body = HTTP.Handlers.handle(ROUTER, req)
    else
        # there's a body, so pass it on to the handler we dispatch to
        response_body = handle(ROUTER, req, JSON2.read(body))
        #@error "request with body, not implemented"
    end

    # wrap the response in an envelope
    #return HTTP.Response(200, JSON2.write(response_body))
    response = Envelope(LAST_UPDATE[], LAST_UPDATE_SERIAL[], now(UTC), response_body)
    return HTTP.Response(200,
                         [("Content-Type" => "application/json")];
                         body=JSON2.write(response)
                        )
end

function updater()
    while true
        @time update()
        @info "updater(): update() done, going to sleep again"
        sleep(5*60)
        @info "updater(): sleep done, running update()"
    end
end

function get_atlas_info()
    pp2atlas = Dict{String}{Vector{NamedTuple}}()
    #TODO: hardcoding page_size is not nice
    jdr_tagged = Atlas.get_my(Dict("tags" => "jdr", "page_size" => "200"))
    @assert length(unique([r.group_id for r in jdr_tagged.results])) == 1
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

function start()
    @info "starting webservice on CPU $(Threads.threadid()) out of $(Threads.nthreads()) available"
    @info "init() ..."
    _init()
    @info "init() done" 

    @info "fetching RIPE Atlas info"
    get_atlas_info()
    @async updater()
    HTTP.serve(JSONHandler, "::1", 8081)
end

end # module

