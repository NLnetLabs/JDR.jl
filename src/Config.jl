module Config

using TOML

export CFG

const LOCAL_CONF_FN = "JDR.toml"
global CFG = Dict()

_CFG = TOML.parse("""
[rpki]
rsync_data_dir  = "rsync_repo"
rrdp_data_dir   = "rrdp_repo"
tal_dir         = "tals"

[rpki.tals]
# Configure which TALs from the tal_dir are processed.
#
# Before uncommenting and using the ARIN TAL, please make sure you read and
# agree with the ARIN RPA:
# https://www.arin.net/resources/manage/rpki/tal/#relying-party-agreement-rpa

#arin       = "arin.tal"
#afrinic    = "afrinic.tal"
#apnic      = "apnic.tal"
#lacnic     = "lacnic.tal"
#ripe       = "ripe.tal"

[webservice]
port = 8081
domain = "http://localhost:8081" # NB: no trailing slash here
atlas_api_key = ""
logfile = "/tmp/jdr.log"

""")

#from https://discourse.julialang.org/t/multi-layer-dict-merge/27261/5 :
#recursively merge kw-dicts
recursive_merge(x::AbstractDict...) = merge(recursive_merge, x...)
# in case of duplicate keys, keep the value from the last dict
recursive_merge(x...) = x[end]

function generate_config()
    global CFG
    if !isempty(CFG)
        @warn "generate_config() called but CFG already contains values"
    end
    CFG = if isfile(LOCAL_CONF_FN)
        @info "found $(LOCAL_CONF_FN)"
        local_cfg = TOML.parsefile(LOCAL_CONF_FN)
        Base.ImmutableDict(recursive_merge(_CFG, local_cfg)...)
    else
        @info "can't find $(LOCAL_CONF_FN)"
        Base.ImmutableDict(_CFG...)
    end
end

function __init__()
    @debug "__init__'ing Config, calling generate_config()"
    generate_config()
end

end # module
