using HTTP
using Dates
using JSON2

using IPNets

using JuliASN

const ROUTER = HTTP.Router()
const APIV = "/api/v1"
const LAST_UPDATE = Ref(now(UTC))
const LAST_UPDATE_SERIAL = Ref(0)
const LOOKUP = Ref(RPKI.Lookup())

include("JSONHelpers.jl")

const TAL_URLS = Dict(
    :afrinic    => "rsync://rpki.afrinic.net/repository/AfriNIC.cer",
    :apnic      => "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
    :arin       => "rsync://rpki.arin.net/repository/arin-rpki-ta.cer",
    :lacnic     => "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer",
    :ripe       => "rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer",
    :ripetest   => "rsync://localcert.ripe.net/ta/RIPE-NCC-TA-TEST.cer",
    :apnictest  => "rsync://rpki-testbed.apnic.net/repository/apnic-rpki-root-iana-origin-test.cer"
)

function asn(req::HTTP.Request)
    # /api/v1/asn/10, get 10
    asid = HTTP.URIs.splitpath(req.target)[4] 
    res = RPKI.lookup(LOOKUP[], RPKI.AutSysNum(parse(UInt32, asid)))
    return [to_root(r) for r in res] 
end

function prefix(req::HTTP.Request)
    # /api/v1/prefix/1.2.3.4%2F24, get and unescape prefix
    prefix = HTTP.URIs.splitpath(req.target)[4] 
    prefix = HTTP.URIs.unescapeuri(prefix)
    prefix = IPNet(prefix)
    res = RPKI.lookup(LOOKUP[], prefix)
    return [to_root(r) for r in res]
end

function object(req::HTTP.Request)
    # /api/v1/object/escaped_filename, get and unescape filename
    object = HTTP.URIs.splitpath(req.target)[4] 
    object = HTTP.URIs.unescapeuri(object)
    res = RPKI.lookup(LOOKUP[], object)
    # res is a Vector or nothing
    res = [ObjectDetails(r.obj) for r in res]
    @debug res
    res
end


function update()
    @info "update()"
    (_, lookup) = fetch(Threads.@spawn(RPKI.retrieve_all(TAL_URLS)))
    LOOKUP[] = lookup
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

function start()
    @info "starting webservice on CPU $(Threads.threadid()) out of $(Threads.nthreads()) available"
    @info "init() ..."
    _init()
    @info "init() done" 
    @async updater()
    HTTP.serve(JSONHandler, "::1", 8081)
end

start()
