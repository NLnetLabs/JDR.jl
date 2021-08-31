module RRDP

using JDR: CFG
using JDR.Common: AutSysNum, NotifyUri
using ..RPKI: RPKIFile, ROA, oneshot, get_pubpoint
#using JDR.RPKICommon: RPKINode, get_object, Lookup

using Base64: base64decode
using CodecZlib
using Dates: DateTime, now, UTC
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

struct RoaDiff
    appeared_v6::Vector
    appeared_v4::Vector
    disappeared_v6::Vector
    disappeared_v4::Vector
    old_asid::Union{Nothing, AutSysNum}
    new_asid::Union{Nothing, AutSysNum}
    old_filename::Union{Nothing, AbstractString}
    new_filename::Union{Nothing, AbstractString}
end

@enum RRDPUpdateType snapshot delta
mutable struct RRDPUpdate
    cer::RPKIFile
    type::RRDPUpdateType
    tstart::DateTime
    tend::DateTime
    #::Lookup?
    stats::RRDPUpdateStats
    new_cers::Vector{AbstractString}
    new_roas::Vector{AbstractString}
    updated_roas::Vector{AbstractString}
    roa_diffs::Vector{RoaDiff}
    withdrawn_roas::Vector{AbstractString}
    errors::Vector{String}
end
function Base.show(io::IO, u::RRDPUpdate) 
    print(io, "[", get_pubpoint(u.cer), "] (", u.tend - u.tstart, ") ")
    if u.type == delta
        print(io, u.stats.deltas_applied, " deltas ")
    else
        print(io, "snapshot ")
    end
    if !isempty(u.errors)
        print(io, "with errors")
    end
    #foreach(f -> println(io, "\t$(f): $(getfield(r,f))"), fieldnames(typeof(r)))
end

#function add(l::Lookup, rrdp_update::RRDPUpdate)
#    reponame = HTTP.URIs.URI(get_object(rrdp_update.cer).rrdp_notify).host
#    #@debug "adding rrdp_update for $(reponame) to lookup"
#    l.rrdp_updates[reponame] = rrdp_update
#end

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

function diff(old::Union{Nothing, RPKIFile{ROA}}, new::Union{Nothing, RPKIFile{ROA}}) :: RoaDiff
    @assert !(isnothing(old) && isnothing(new))

    appeared_v6 = []
    appeared_v4 = []
    disappeared_v6 = []
    disappeared_v4 = []
    old_asid = nothing
    new_asid = nothing
    old_filename = new_filename = nothing

    if isnothing(old)
        # return all from new as appeared
        appeared_v6 = collect(new.object.vrp_tree.resources_v6)
        appeared_v4 = collect(new.object.vrp_tree.resources_v4)
        new_asid = new.object.asid
        new_filename = new.filename
    elseif isnothing(new)
        # return all from old as disappeared
        disappeared_v6 = collect(old.object.vrp_tree.resources_v6)
        disappeared_v4 = collect(old.object.vrp_tree.resources_v4)
        old_asid = old.object.asid
        old_filename = old.filename
    else
        # actuall diff
        # check asid: if not the same, full set of old is disappeared, full
        old_asid = old.object.asid
        new_asid = new.object.asid
        old_filename = old.filename
        new_filename = new.filename
        if old.object.asid != new.object.asid
            @debug "different asids: $(old.object.asid) vs $(new.object.asid)"
            appeared_v6 = collect(new.object.vrp_tree.resources_v6)
            appeared_v4 = collect(new.object.vrp_tree.resources_v4)
            disappeared_v6 = collect(old.object.vrp_tree.resources_v6)
            disappeared_v4 = collect(old.object.vrp_tree.resources_v4)
        else
            @warn "ROA diff, same asid $(new.object.asid) for $(new_filename)\nsha256 of new roa: $(bytes2hex(sha256(read(new_filename))))"
            # tmp analsysis
            ts = now().instant.periods.value >> 8
            cp(new_filename, joinpath("debug", basename(new_filename)*".$(ts).new.roa"))
            # v6:
            old_set = collect(old.object.vrp_tree.resources_v6)
            new_set = collect(new.object.vrp_tree.resources_v6)
            disappeared_v6 = setdiff(old_set, new_set)
            appeared_v6 = setdiff(new_set, old_set)

            # v4:
            old_set = collect(old.object.vrp_tree.resources_v4)
            new_set = collect(new.object.vrp_tree.resources_v4)
            disappeared_v4 = setdiff(old_set, new_set)
            appeared_v4 = setdiff(new_set, old_set)

            @warn new_filename disappeared_v6 appeared_v6 disappeared_v4 appeared_v4

            #TODO actuall diff
            #throw("TODO implement actuall roa vrp set diff")
        end
        # set of new is appeared
        # calculate disappeared from old not in new
        # appeared from new not in old
        # return both
    end

    RoaDiff(appeared_v6,
            appeared_v4,
            disappeared_v6,
            disappeared_v4,
            old_asid,
            new_asid,
            old_filename,
            new_filename
           )
end

# works on both snapshot and delta XMLs
function _process_publish_withdraws(rrdp_update::RRDPUpdate, doc::EzXML.Document)
    reponame = HTTP.URIs.URI(rrdp_update.cer.object.rrdp_notify.u).host
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

        filename_old = uri_to_path(p_or_w["uri"], false)
        filename = uri_to_path(p_or_w["uri"], use_tmp_dir)
        calc_roa_diff = false
        old_roa = new_roa = nothing
        if nodename(p_or_w) == "publish"
            #TODO:
            #make a clearer distinction between snapshot fetch and delta-based #update
            #if snapshot, do not calculate old_roa, and do not push rrdp_update.update_roas
            #we can still calc the diffs afterwards, not show them in jdr-web, but keep them around
            #for longer term storage (for historical analytics etc)

            if rrdp_update.type == snapshot
                # snapshot update, do not care about existing old files
                # we will calculate the diff comparing to old_roa=nothing
                if endswith(filename, r"\.cer"i)
                    push!(rrdp_update.new_cers, filename)
                elseif endswith(filename, r"\.roa"i)
                    #calc_roa_diff = true # FIXME 'too expensive' in the current code
                    push!(rrdp_update.new_roas, filename)
                end
            else
                # delta update. if this file exists, consider it an update, and calculate the diff
                # accordingly
                if isfile(filename_old)
                    # file exists, so this is an update
                    rrdp_update.stats.updates += 1

                    if endswith(filename, r"\.roa"i)
                        # tmp analysis
                        @debug "copying $filename_old to ./debug/\nsha256 of existing roa: $(bytes2hex(sha256(read(filename_old))))"
                        ts = now().instant.periods.value >> 8
                        cp(filename_old, joinpath("debug", basename(filename_old)*".$(ts).old.roa"))
                        # eotmp
                    
                        push!(rrdp_update.updated_roas, filename_old)
                        calc_roa_diff = true
                        old_roa = oneshot(filename_old)
                    end
                else
                    # file does not exist yet, new publish
                    rrdp_update.stats.new_publishes += 1
                    if endswith(filename, r"\.cer"i)
                        push!(rrdp_update.new_cers, filename)
                    elseif endswith(filename, r"\.roa"i)
                        calc_roa_diff = true
                        push!(rrdp_update.new_roas, filename)
                    end
                end
            end

            #---
            #@assert !use_tmp_dir || (use_tmp_dir && !isfile(filename_old))
            #if isfile(filename_old)
            #    rrdp_update.stats.updates += 1
            #    if endswith(filename, r"\.roa"i)
            #        push!(rrdp_update.updated_roas, filename_old)
            #        calc_roa_diff = true
            #        old_roa = oneshot(filename_old)
            #    end
            #else
            #    rrdp_update.stats.new_publishes += 1
            #    if endswith(filename, r"\.cer"i)
            #        push!(rrdp_update.new_cers, filename)
            #    elseif endswith(filename, r"\.roa"i)
            #        calc_roa_diff = true
            #        #new_roa = oneshot(filename) # does not exist here yet!
            #        push!(rrdp_update.new_roas, filename)
            #    end
            #end
            increase_stats(rrdp_update.stats.publishes_per_type, filename)

            mkpath(dirname(filename))
            write(filename, base64decode(nodecontent(p_or_w)))
            if calc_roa_diff
                new_roa = oneshot(filename)
            end
        elseif nodename(p_or_w) == "withdraw"
            @assert rrdp_update.type == delta
            rrdp_update.stats.withdraws += 1
            increase_stats(rrdp_update.stats.withdraws_per_type, filename_old)

            if !isfile(filename_old)
                @warn "[$(reponame)] File $(filename_old) to be withdrawn, but not found on disk"
            else
                if endswith(filename_old, r"\.roa"i)
                    old_roa = oneshot(filename_old)
                    @assert isnothing(new_roa)
                    push!(rrdp_update.withdrawn_roas, filename_old)
                end
                rm(filename_old)
                while length(readdir(dirname(filename_old))) == 0
                    @debug "$(dirname(filename_old)) empty, removing"
                    rm(dirname(filename_old))
                    filename_old = dirname(filename_old)
                end
            end
        else
            @error "[$(reponame)] not publish nor withdraw, invalid xml?"
        end
        if !(isnothing(old_roa) && isnothing(new_roa)) 
            roa_diff = diff(old_roa, new_roa)
            push!(rrdp_update.roa_diffs, roa_diff)
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
        if e isa HTTP.ExceptionRequest.StatusError
            @warn url e.status e.target
        else
            @warn url e
            #display(stacktrace(catch_backtrace()))
        end
        push!(rrdp_update.errors, string(typeof(e)))
        return false
    end

    return true
end

function validate_notification(rrdp_update::RRDPUpdate, doc::EzXML.Document)
    @warn "TODO implement validate_notification" maxlog=3
end

#function fetch_process_notification(url::AbstractString)
function fetch_process_notification(cer_rf::RPKIFile) :: RRDPUpdate
    rrdp_update = RRDPUpdate(cer_rf, snapshot, now(UTC), now(UTC), RRDPUpdateStats(), [], [], [], [], [], [])
    url = cer_rf.object.rrdp_notify.u
    reponame = HTTP.URIs.URI(url).host
    @debug "[$(reponame)] Fetching $(url)"

    doc = try
        possibly_zipped = HTTP.get(url; httpconf...).body
        @debug "[$(reponame)] Fetch notification.xml done, got $(length(possibly_zipped)) bytes"
        gunzip(possibly_zipped) |> parsexml
    catch e
        if e isa HTTP.ExceptionRequest.StatusError
            @warn url e.status e.target
        else
            @warn url e
            #display(stacktrace(catch_backtrace()))
        end
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
        rrdp_update.type = delta
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

    rrdp_update.tend = now(UTC)
    return rrdp_update
end

function fetch_ta_cer(url::NotifyUri, output_fn::AbstractString)
    @debug "fetch_ta_cer for $(url.u)"
    try
        mkpath(dirname(output_fn))
        write(output_fn, gunzip(HTTP.get(url.u; httpconf...).body))
    catch e
        @error "Could not retrieve TA cer from $(url.u): ", e
    end
end

end
