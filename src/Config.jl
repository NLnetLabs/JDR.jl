module Config
using TOML

const LOCAL_CONF_FN = "JDR.toml"

_CFG = TOML.parse("""
[rpki]
rsyncrepo   = "$(ENV["HOME"])/.rpki-cache/repository/rsync"

[rpki.tals]
afrinic    = "rsync://rpki.afrinic.net/repository/AfriNIC.cer"
apnic      = "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer"
arin       = "rsync://rpki.arin.net/repository/arin-rpki-ta.cer"
lacnic     = "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer"
ripe       = "rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer"

[webservice]
port = 8081
domain = "http://localhost:8081/"
atlas_api_key = ""

""")

const CFG = if isfile(LOCAL_CONF_FN)
    @info "found $(LOCAL_CONF_FN)"
    local_cfg = TOML.parsefile(LOCAL_CONF_FN)
    Base.ImmutableDict(merge(_CFG, local_cfg)...)
else
    Base.ImmutableDict(_CFG...)
end

end # module
