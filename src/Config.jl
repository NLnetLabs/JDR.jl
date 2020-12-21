module Config
using TOML

const LOCAL_CONF_FN = "JDR.toml"
global CFG = Dict()

_CFG = TOML.parse("""
[rpki]
rsyncrepo   = "$(ENV["HOME"])/.rpki-cache/repository/rsync"

[rpki.tals]
# Before uncommenting and using the ARIN TAL, please make sure you read and
# agree with the ARIN RPA:
# https://www.arin.net/resources/manage/rpki/tal/#relying-party-agreement-rpa
#
#arin       = "rsync://rpki.arin.net/repository/arin-rpki-ta.cer"
#afrinic    = "rsync://rpki.afrinic.net/repository/AfriNIC.cer"
#apnic      = "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer"
#lacnic     = "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer"
#ripe       = "rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer"

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

end # module
