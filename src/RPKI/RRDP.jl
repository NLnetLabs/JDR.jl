module RRDP

using JDR: CFG
using JDR.RPKICommon: RPKINode, get_object, Lookup

using Base64: base64decode
using CodecZlib
using EzXML
using HTTP
using SHA
using TOML

export fetch_ta_cer, fetch_process_notification

function uri_to_path(uri::AbstractString, tmp::Bool)
    path = if tmp
            joinpath(CFG["rpki"]["rrdp_data_dir"], "tmp", uri[9:end])
        else
            joinpath(CFG["rpki"]["rrdp_data_dir"], uri[9:end])
        end

    return path
end

httpconf = (connect_timeout = 5,
            retries = 3,
            readtimeout = 5,
            headers = ["Accept-Encoding" => "gzip,deflate"]
           )

function gunzip(raw::Vector{UInt8}) :: Vector{UInt8}
    if HTTP.iscompressed(raw)
        transcode(GzipDecompressor, raw)
    else
        raw
    end
end

mutable struct FiletypeStats
    cer::Int
    mft::Int
    crl::Int
    roa::Int
    other::Int
end
FiletypeStats() = FiletypeStats(0, 0, 0, 0, 0)
Base.show(io::IO, fts::FiletypeStats) = print(io,
                                                "CERs: ", fts.cer,
                                                " MFTs: ", fts.mft,
                                                " CRLs: ", fts.crl,
                                                " ROAs: ", fts.roa)

mutable struct RRDPUpdateStats
    deltas_applied::Int
    new_publishes::Int
    updates::Int
    withdraws::Int
    bytes_transferred::Int
    bytes_delta::Int
    requests_needed::Int
    publishes_per_type::FiletypeStats
    withdraws_per_type::FiletypeStats
end
RRDPUpdateStats() = RRDPUpdateStats(0, 0, 0, 0, 0, 0, 0, FiletypeStats(), FiletypeStats())
Base.show(io::IO, r::RRDPUpdateStats) = foreach(f -> println(io, "\t$(f): $(getfield(r,f))"), fieldnames(typeof(r)))

@enum RRDPUpdateType snapshot delta
mutable struct RRDPUpdate
    cer::RPKINode
    type::RRDPUpdateType
    #::Lookup?
    stats::RRDPUpdateStats
    new_cers::Vector{AbstractString}
    new_roas::Vector{AbstractString}
    errors::Vector{String}
end

function add(l::Lookup, rrdp_update::RRDPUpdate)
    reponame = HTTP.URIs.URI(get_object(rrdp_update.cer).rrdp_notify).host
    #@debug "adding rrdp_update for $(reponame) to lookup"
    l.rrdp_updates[reponame] = rrdp_update
end

function increase_stats(stats::FiletypeStats, filename::AbstractString)
    if endswith(filename, r"\.cer"i)
        stats.cer += 1
    elseif endswith(filename, r"\.mft"i)
        stats.mft += 1
    elseif endswith(filename, r"\.crl"i)
        stats.crl += 1
    elseif endswith(filename, r"\.roa"i)
        stats.roa += 1
    else
        stats.other += 1
    end
end

# works on both snapshot and delta XMLs
function _process_publish_withdraws(rrdp_update::RRDPUpdate, doc::EzXML.Document)
    reponame = HTTP.URIs.URI(get_object(rrdp_update.cer).rrdp_notify).host
    use_tmp_dir = rrdp_update.type == snapshot
    repodir = ""
    dont_mv = false

    for p_or_w in elements(doc.root)
        if repodir == ""
            repodir = HTTP.URIs.URI(p_or_w["uri"]).host
        elseif repodir != HTTP.URIs.URI(p_or_w["uri"]).host
            @warn "[$(reponame)] expected hostname $(repodir), got $(HTTP.URIs.URI(p_or_w["uri"]).host)"
            dont_mv = true
        end

        filename = uri_to_path(p_or_w["uri"], use_tmp_dir)
        if nodename(p_or_w) == "publish"
            if isfile(filename)
                rrdp_update.stats.updates += 1
            else
                rrdp_update.stats.new_publishes += 1
                if endswith(filename, r"\.cer"i)
                    push!(rrdp_update.new_cers, filename)
                elseif endswith(filename, r"\.roa"i)
                    push!(rrdp_update.new_roas, filename)
                end
            end
            increase_stats(rrdp_update.stats.publishes_per_type, filename)

            mkpath(dirname(filename))
            write(filename, base64decode(nodecontent(p_or_w)))
        elseif nodename(p_or_w) == "withdraw"
            @assert rrdp_update.type == delta
            rrdp_update.stats.withdraws += 1
            increase_stats(rrdp_update.stats.withdraws_per_type, filename)

            if !isfile(filename)
                @warn "[$(reponame)] File $(filename) to be withdrawn, but not found on disk"
            else
                rm(filename)
                while length(readdir(dirname(filename))) == 0
                    @debug "$(dirname(filename)) empty, removing"
                    rm(dirname(filename))
                    filename = dirname(filename)
                end
            end
        else
            @error "[$(reponame)] not publish nor withdraw, invalid xml?"
        end
    end

    if rrdp_update.type == snapshot
        if dont_mv
            @warn "[$(reponame)] something went wrong, not mv'ing tmpdir over existing dir.
            Fix this by manually remove directories from rrdp_data_dir."
        else
            existing_dir = joinpath(CFG["rpki"]["rrdp_data_dir"], repodir)
            tmp_dir = joinpath(CFG["rpki"]["rrdp_data_dir"], "tmp", repodir)
            if !isdir(tmp_dir)
                @error "[$(reponame)] expected $(tmp_dir), but it is not there, bailing out"
            else
                if !isdir(existing_dir)
                    @warn "[$(reponame)] expected $(existing_dir), but it is not there"
                    @debug "mv: $(tmp_dir) -> $(existing_dir)"
                    mv(tmp_dir, existing_dir)
                else
                    mv(tmp_dir, existing_dir, force=true)
                    @debug "mv over existing: $(tmp_dir) -> $(existing_dir)"
                end
            end
        end
    end

end

function fetch_process_delta(rrdp_update::RRDPUpdate, delta_node::EzXML.Node, session_notification::AbstractString)
    url = delta_node["uri"] 
    try
        response = HTTP.get(url; httpconf...)
        raw = gunzip(response.body)
        if bytes2hex(sha256(raw)) != lowercase(delta_node["hash"])
            @warn "Invalid hash for $(url)"
        end
        bytes_transferred = length(raw)
        doc = parsexml(raw)
        if doc.root["session_id"] != session_notification
            @error "session_id in delta $(doc.root["serial"]) different from notification, falling back to snapshot TODO"
            return false
        end
        _process_publish_withdraws(rrdp_update, doc)
        rrdp_update.stats.deltas_applied += 1
        rrdp_update.stats.bytes_transferred += bytes_transferred
        rrdp_update.stats.requests_needed += response.request.txcount
    catch e
        @warn url e
        push!(rrdp_update.errors, string(typeof(e)))
        return false
    end

    return true
end


function fetch_process_snapshot(rrdp_update::RRDPUpdate, snapshot_node::EzXML.Node)
    url = snapshot_node["uri"]
    try
        @debug "fetching snapshot from $(url)"
        response = HTTP.get(url; httpconf...)
        raw = gunzip(response.body)
        if bytes2hex(sha256(raw)) != lowercase(snapshot_node["hash"])
            @warn "Invalid hash for $(url)"
            # TODO remark on node
        end
        bytes_transferred = length(raw)
        doc = parsexml(raw)
        _process_publish_withdraws(rrdp_update, doc)
        rrdp_update.stats.bytes_transferred += bytes_transferred
        rrdp_update.stats.requests_needed += response.request.txcount
    catch e
        @warn url e
        push!(rrdp_update.errors, string(typeof(e)))
        return false
    end

    return true
end

function validate_notification(rrdp_update::RRDPUpdate, doc::EzXML.Document)
    @warn "TODO implement validate_notification" maxlog=3
end

#function fetch_process_notification(url::AbstractString)
function fetch_process_notification(cer_node::RPKINode) :: RRDPUpdate
    rrdp_update = RRDPUpdate(cer_node, snapshot, RRDPUpdateStats(), [], [], [])
    url = get_object(cer_node).rrdp_notify
    reponame = HTTP.URIs.URI(get_object(cer_node).rrdp_notify).host
    @debug "[$(reponame)] Fetching $(url)"

    doc = try
        possibly_zipped = HTTP.get(url; httpconf...).body
        @debug "[$(reponame)] Fetch notification.xml done, got $(length(possibly_zipped)) bytes"
        gunzip(possibly_zipped) |> parsexml
    catch e
        @warn reponame url e
        rrdp_update.errors = [string(typeof(e))]
        return rrdp_update
    end

    validate_notification(rrdp_update, doc)

    repodir = joinpath(CFG["rpki"]["rrdp_data_dir"], HTTP.URIs.URI(firstelement(doc.root)["uri"]).host)
    rrdp_state = nothing
    state_fn = joinpath(CFG["rpki"]["rrdp_data_dir"], "jdr_state", "$(reponame).toml")
    mkpath(dirname(state_fn))
    if isfile(state_fn)
        rrdp_state = TOML.parsefile(state_fn)
    else
        @warn reponame "can not find file $(state_fn), pwd: $(pwd())"
    end

    # extract serial
    serial_them = parse(Int, doc.root["serial"])
    session_them = doc.root["session_id"]
    # compare serial
    serial_us = if !isnothing(rrdp_state)
        rrdp_state["serial"]
    else
        nothing
    end

    success = false

    if isnothing(rrdp_state)
        @info "[$(reponame)] no local state for $(url), fetching snapshot"
        success = fetch_process_snapshot(rrdp_update, firstelement(doc.root))
    elseif rrdp_state["session_id"] != session_them
        @warn "[$(reponame)] new session_id $(session_them), fetching snapshot"
        success = fetch_process_snapshot(rrdp_update, firstelement(doc.root))
    elseif serial_them == serial_us
        @info "[$(reponame)] serial_them == serial_us == $(serial_them), session_id matches, already up to date"
        success = true
    elseif serial_them > serial_us
        need = (serial_us+1:serial_them)
        @info "[$(reponame)] serial_them $(serial_them), serial_us $(serial_us), need $(need) ($(length(need)))"
        deltas = filter(n -> nodename(n) == "delta", elements(doc.root))
        sort!(deltas; by = d -> d["serial"])
        serials = map(d -> parse(Int, d["serial"]), deltas )
        if all(s -> s in serials, need)
            rrdp_update.type = delta
            success = all(
                          map(d -> fetch_process_delta(rrdp_update, d, session_them),
                              filter(d -> parse(Int, d["serial"]) in need, deltas)
                             )
                         )
        else
            @warn "[$(reponame)] need older deltas than available, falling back to snapshot"
            success = fetch_process_snapshot(rrdp_update, firstelement(doc.root))
        end
    else # so them < us
        @error "[$(reponame)] serial them < serial us, should never happen"
        #TODO fallback to snapshot?
    end

    # done, update state
    if success
        rrdp_state = Dict("serial" => serial_them, "session_id" => session_them)
        open(state_fn, "w+") do io
            TOML.print(io, rrdp_state)
        end
    else
        @warn "[$(reponame)] failed to update, removing state file thus forcing a snapshot fetch next time"
        if isfile(state_fn)
            rm(state_fn)
        end
    end

    return rrdp_update
end

function fetch_ta_cer(url::AbstractString, output_fn::AbstractString)
    @debug "fetch_ta_cer for $(url)"
    try
        mkpath(dirname(output_fn))
        write(output_fn, gunzip(HTTP.get(url; httpconf...).body))
    catch e
        @error "Could not retrieve TA cer from $(url): ", e
    end
end

end
