module Cer

using ...JDR.Common
using ...RPKI
using ...ASN1
using ...PKIX.X509
using SHA

export check_ASN1, check_cert, check_resources

import .RPKI:check_ASN1
function check_ASN1(o::RPKIObject{CER}, tpi::TmpParseInfo=TmpParseInfo()) :: RPKIObject{CER}
    # The certificate should consist of three parts: (RFC5280)
	# Certificate  ::=  SEQUENCE  {
	#      tbsCertificate       TBSCertificate,
	#      signatureAlgorithm   AlgorithmIdentifier,
	#      signature            BIT STRING  }
    

    childcount(o.tree, 3) # this one marks the SEQUENCE as checked!
    tbsCertificate = o.tree.children[1]
    X509.check_ASN1_tbsCertificate(o, tbsCertificate, tpi)
    
    o
end

function check(o::RPKIObject{CER}, tpi::TmpParseInfo=TmpParseInfo())
    @warn "DEPRECATED CER.check(), use CER.check_ASN1()" maxlog=3
    check_ASN1(o, tpi)
end

import .RPKI:check_cert
function check_cert(o::RPKIObject{CER}, tpi::TmpParseInfo) :: RPKI.RPKIObject{CER}
    if !o.object.selfsigned && tpi.certStack[end-1].subject != o.object.issuer
        @error "subject != issuer for child cert $(o.filename)"
        err!(o, "subject != issuer for child cert")
    end
    sig = o.tree.children[3]
    signature = to_bigint(sig.tag.value[2:end])
    @assert !isnothing(o.object.selfsigned)
    v = if o.object.selfsigned
        powermod(signature, tpi.certStack[end].rsa_exp, tpi.certStack[end].rsa_modulus)
    else
        powermod(signature, tpi.certStack[end-1].rsa_exp, tpi.certStack[end-1].rsa_modulus)
    end
    v.size = 4
    v_str = string(v, base=16, pad=64)

    tbs_raw = read(o.filename, o.tree[2].tag.offset_in_file-1)[o.tree[1].tag.offset_in_file:end]
    my_hash = bytes2hex(sha256(tbs_raw))

    # this only described whether the signature is valid or not! no resource
    # checks done at this point
    tpi.certValid = v_str == my_hash
    o
end

# TODO: add a resourcesValid flag somewhere
# and perhaps, on the RPKINode level, create a pointer to the covering CER
function check_resources(o::RPKIObject{CER}, tpi::TmpParseInfo)
    if !o.object.selfsigned
        if isempty(o.object.ASNs) && !o.object.inherit_ASNs
            #@error "empty ASNs and no inheritance? $(o.filename)" maxlog=3
            warn!(o, "empty ASNs but no inherit")
        end
        if !covered(o.object.ASNs , tpi.certStack[end-1].ASNs)
            # not covered, so check for inherited ASNs in parent certificates
            @assert tpi.certStack[end-1].inherit_ASNs
            for parent in reverse(tpi.certStack[1:end-2])
                if !parent.inherit_ASNs
                    @assert covered(o.object.ASNs, parent.ASNs)
                    #@debug "$(o.filename) covered by $(parent.issuer)"
                    return
                end
            end

            @error "illegal ASNs in $(o.filename)"
            @debug o.object.ASNs
            @debug tpi.certStack[end-1].ASNs
            throw("illegal resources")
        end
    end
end

end # module
