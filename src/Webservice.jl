using HTTP
using Dates
using JSON2

using JuliASN

const ROUTER = HTTP.Router()
const APIV = "/api/v1"
const LAST_UPDATE = Ref(now(UTC))
const LAST_UPDATE_SERIAL = Ref(0)
const LOOKUP = Ref(RPKI.Lookup())


function asn(req::HTTP.Request)
    asid = HTTP.URIs.splitpath(req.target)[4] # /api/v1/asn/10, get 10
    @info "returning for asn()"
    return "fake results for ASN $(asid)"
end

function prefix(req::HTTP.Request)
    prefix = HTTP.URIs.splitpath(req.target)[4] # /api/v1/prefix/10, get 10
    prefix = HTTP.URIs.unescapeuri(prefix)
    return "fake results for prefix $(prefix)"
end


function update()
    @info "update()"
    (_, lookup) = fetch(Threads.@spawn(RPKI.retrieve_all()))
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
    HTTP.@register(ROUTER, "GET", APIV*"/update", update)
end

struct Envelope
    last_update::DateTime
    serial::Integer
    timestamp::DateTime
    data::Any
end

function set_last_update()
    LAST_UPDATE[] = now(UTC) + Hour(6)
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
    return HTTP.Response(200, JSON2.write(response))
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

    HTTP.serve(JSONHandler, "::1", 8081)
end

start()
