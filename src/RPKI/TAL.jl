module Tal

using JDR.ASN1: to_bigint
using JDR.ASN1.DER: DER

using JDR.Common: NotifyUri, RsyncUri

using Base64

export TAL, parse_tal

struct TAL
    rsync::Union{Nothing, RsyncUri}
    rrdp::Union{Nothing, NotifyUri}
    key::BigInt
end

function parse_tal(fn::AbstractString)
    buf = IOBuffer(read(fn))

    # skip comments, if any
    line = readline(buf)
    while line[1] == '#'
        line = readline(buf)
    end

    # the URIs 
    rsync = rrdp = nothing
    while !isempty(line)
        if @view(line[1:8]) == "https://"
            rrdp = NotifyUri(line)
        elseif @view(line[1:8]) == "rsync://"
            rsync = RsyncUri(line)
        else
            @warn "Unknown URI format $(line)"
        end
        line = readline(buf)
    end

    # and finally the key
    b64 = join(readlines(buf))
    der = base64decode(b64)
    asn1 = DER.parse_recursive(DER.Buf(der))

    # first byte of bitstring indicates number of unused bits in last byte
    # should be 0 
    @assert asn1[2].tag.value[1] == 0x0
    encaps_buf = DER.Buf(asn1[2].tag.value[2:end])
    DER.parse_append!(encaps_buf, asn1[2])

    return TAL(rsync, rrdp, to_bigint(@view asn1[2,1,1].tag.value[2:end]))
end

end
