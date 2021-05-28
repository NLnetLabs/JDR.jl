module RRDP

using JDR: CFG

using Base64: base64decode
using EzXML
using HTTP

export fetch_ta_cer, fetch_snapshot

function uri_to_path(uri::AbstractString)
    path = joinpath(CFG["rpki"]["rrdp_data_dir"], uri[9:end])
    path
end

function _fetch_publish(url::AbstractString)
    try
        doc = HTTP.get(url).body |> parsexml
        publishes = elements(doc.root)
        @debug "serial $(doc.root["serial"]), $(length(publishes)) publishes"

        for p in publishes
            filename = uri_to_path(p["uri"])
            mkpath(dirname(filename))
            write(filename, base64decode(nodecontent(p)))
        end
    catch e
        @warn e
        return
    end
end

function fetch_snapshot(url::AbstractString)
    try
        doc = HTTP.get(url; connect_timeout = 5).body |> parsexml
        snapshot_url = firstelement(doc.root)["uri"]
        @debug "fetching $(snapshot_url)"
        _fetch_publish(snapshot_url)
    catch e
        @warn e
        return
    end
end

function fetch_ta_cer(url::AbstractString, output_fn::AbstractString)
    try
        mkpath(dirname(output_fn))
        write(output_fn, HTTP.get(url; connect_timeout = 5).body)
    catch e
        @error "Could not retrieve TA cer from $(url): ", e
    end
end

end
