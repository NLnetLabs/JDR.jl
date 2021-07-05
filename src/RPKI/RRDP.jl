module RRDP

using JDR: CFG

using Base64: base64decode
using EzXML
using HTTP
using SHA
using TOML

export fetch_ta_cer, fetch_process_notification

function uri_to_path(uri::AbstractString)
    path = joinpath(CFG["rpki"]["rrdp_data_dir"], uri[9:end])
    path
end

# works on both snapshot and delta XMLs
function _process_publish_withdraws(doc::EzXML.Document)
    for p_or_w in elements(doc.root)
        filename = uri_to_path(p_or_w["uri"])
        if nodename(p_or_w) == "publish"
            #if isfile(filename)
            #    #update to existing file
            #end
            mkpath(dirname(filename))
            write(filename, base64decode(nodecontent(p_or_w)))
        elseif nodename(p_or_w) == "withdraw"
            if !isfile(filename)
                @warn "File $(filename) to be withdrawn, but not found on disk"
            else
                @info "withdrawn: $(filename)"
                rm(filename)
                while length(readdir(dirname(filename))) == 0
                    @debug "$(dirname(filename)) empty, removing"
                    #rm(dirname(filename))
                    filename = dirname(filename)
                end
            end
        else
            @error "not publish nor withdraw, invalid xml?"
        end
    end
end

function fetch_process_delta(delta_node::EzXML.Node)
    url = delta_node["uri"] 
    try
        raw = HTTP.get(url; connect_timeout = 5, retries=3).body
        if bytes2hex(sha256(raw)) != lowercase(delta_node["hash"])
            @warn "Invalid hash for $(url)"
        end
        doc = parsexml(raw)
        _process_publish_withdraws(doc)
    catch e
        @warn e
        return
    end

end


function fetch_process_snapshot(snapshot_node::EzXML.Node)
    try
        url = snapshot_node["uri"]
        @debug "fetching snapshot from $(url)"
        raw = HTTP.get(url; connect_timeout = 5, retries=3).body
        if bytes2hex(sha256(raw)) != lowercase(snapshot_node["hash"])
            @warn "Invalid hash for $(url)"
        end
        doc = parsexml(raw)
        _process_publish_withdraws(doc)
    catch e
        @warn e
        return
    end
end

function validate_notification(doc::EzXML.Document)
    @warn "TODO implement validate_notification" maxlog=3
end

function fetch_process_notification(url::AbstractString)
    @debug "Fetching $(url)"

    doc = try
        HTTP.get(url; connect_timeout = 5, retries=3).body |> parsexml
    catch e
        @warn e
        return nothing
    end

    validate_notification(doc)

    repodir = joinpath(CFG["rpki"]["rrdp_data_dir"], HTTP.URIs.URI(firstelement(doc.root)["uri"]).host)
    @debug repodir
    rrdp_state = nothing
    state_fn = joinpath(repodir, "jdr_rrdp_state.toml")
    if isdir(repodir)
        if isfile(state_fn)
            rrdp_state = TOML.parsefile(state_fn)
            #@debug rrdp_state
        else
            @debug "can not find file $(state_fn), pwd: $(pwd())"
        end
    else 
        @debug "can not find dir $(repodir), making it though it will likely only hold a JDR state file"
        mkpath(repodir)
    end

    # extract serial
    them = parse(Int, doc.root["serial"])
    # compare serial
    us = if !isnothing(rrdp_state)
        rrdp_state["serial"]
    else
        nothing
    end

    if isnothing(us)
        @info "us == nothing, fetching snapshot"
        fetch_process_snapshot(firstelement(doc.root))
    elseif them == us
        @info "them == us == $(them), already up to date"
    elseif them > us
        need = (us+1:them)
        @info "them $(them), us $(us), need $(need)"
        deltas = filter(n -> nodename(n) == "delta", elements(doc.root))
        sort!(deltas; by = d -> d["serial"])
        serials = map(d -> parse(Int, d["serial"]), deltas )
        if all(s -> s in serials, need)
            @debug "all necessary deltas available"
            fetch_process_delta.(filter(d -> parse(Int, d["serial"]) in need, deltas))
        else
            @debug "need older deltas than available, falling back to snapshot"
            fetch_process_snapshot(firstelement(doc.root))
        end
    else # so them < us
        @error "serial them < serial us, should never happen"
    end

    # done, update state
    rrdp_state = Dict("serial" => them)
    open(state_fn, "w+") do io
        TOML.print(io, rrdp_state)
    end
end

function fetch_ta_cer(url::AbstractString, output_fn::AbstractString)
    @debug "fetch_ta_cer for $(url)"
    try
        mkpath(dirname(output_fn))
        write(output_fn, HTTP.get(url; connect_timeout = 5, retries=3).body)
    catch e
        @error "Could not retrieve TA cer from $(url): ", e
    end
end

end
