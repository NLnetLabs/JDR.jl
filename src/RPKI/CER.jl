module Cer

using JDR.Common: IPRange, covered, check_coverage, remark_validityIssue!, remark_resourceIssue!
using JDR.RPKI:RPKIObject, CER, TmpParseInfo
using JDR.RPKICommon: RPKINode
using JDR.ASN1: childcount, to_bigint
using JDR.PKIX.X509: X509
using SHA: sha256
using IntervalTrees: IntervalValue
using Sockets: IPv6, IPv4

import ..RPKI # to extend check_ASN1, check_cert, add_resource!, check_resources

"""
    check_ASN1(o::RPKIObject{CER})
Validate the ASN1 structure of `o.tree`
"""
function RPKI.check_ASN1(o::RPKIObject{CER}, tpi::TmpParseInfo=TmpParseInfo()) :: RPKIObject{CER}
    # The certificate should consist of three parts: (RFC5280)
	# Certificate  ::=  SEQUENCE  {
	#      tbsCertificate       TBSCertificate,
	#      signatureAlgorithm   AlgorithmIdentifier,
	#      signature            BIT STRING  }
    

    childcount(o.tree, 3) # this one marks the SEQUENCE as checked!
    tbsCertificate = o.tree.children[1]
    X509.check_ASN1_tbsCertificate(o, tbsCertificate, tpi)
    X509.check_ASN1_signatureAlgorithm(o, o.tree.children[2], tpi)
    X509.check_ASN1_signatureValue(o, o.tree.children[3], tpi)
    o
end

function RPKI.check_cert(o::RPKIObject{CER}, tpi::TmpParseInfo) :: RPKIObject{CER}
    if !o.object.selfsigned && tpi.certStack[end-1].subject != o.object.issuer
        @error "subject != issuer for child cert $(o.filename)"
        remark_validityIssue!(o, "subject != issuer for child cert")
    end
    sig = o.tree.children[3]
    signature = to_bigint(@view sig.tag.value[2:end])
    @assert !isnothing(o.object.selfsigned)
    v = if o.object.selfsigned
        powermod(signature, tpi.certStack[end].rsa_exp, tpi.certStack[end].rsa_modulus)
    else
        powermod(signature, tpi.certStack[end-1].rsa_exp, tpi.certStack[end-1].rsa_modulus)
    end
    v.size = 4
    v_str = string(v, base=16, pad=64)

    tbs_raw = @view o.tree.buf.data[o.tree[1].tag.offset_in_file:o.tree[2].tag.offset_in_file-1]
    my_hash = bytes2hex(sha256(tbs_raw))

    # this only described whether the signature is valid or not! no resource
    # checks done at this point
    if v_str == my_hash
        o.sig_valid = true
    else
        remark_validityIssue!(o, "invalid signature")
        o.sig_valid = false
    end
    o
end

function RPKI.add_resource!(cer::CER, minaddr::IPv6, maxaddr::IPv6)
	push!(cer.resources_v6, IntervalValue(minaddr, maxaddr, RPKINode[]))
end
function RPKI.add_resource!(cer::CER, minaddr::IPv4, maxaddr::IPv4)
	push!(cer.resources_v4, IntervalValue(minaddr, maxaddr, RPKINode[]))
end

RPKI.add_resource!(cer::CER, ipr::IPRange{IPv6}) = push!(cer.resources_v6, IntervalValue(ipr, RPKINode[]))
RPKI.add_resource!(cer::CER, ipr::IPRange{IPv4}) = push!(cer.resources_v4, IntervalValue(ipr, RPKINode[]))


function RPKI.check_resources(o::RPKIObject{CER}, tpi::TmpParseInfo)
    o.object.resources_valid = true
    if !o.object.selfsigned
        if !covered(o.object.ASNs , tpi.certStack[end-1].ASNs)
            _covered = false
            # not covered, so check for inherited ASNs in parent certificates
            for parent_cer in reverse(tpi.certStack[1:end-2])
                if !parent_cer.inherit_ASNs
                    if !covered(o.object.ASNs, parent_cer.ASNs)
                        @warn "illegal ASNs for $(o.filename)"
                        remark_validityIssue!(o, "illegal ASNs")
                        o.object.resources_valid = false
                    end
                    _covered = true
                    break
                end
            end
            if !_covered
                # The only way to reach this is if any of the RIR certs has no
                # ASNs (which is already wrong) and also no inheritance
                @error "ASN inheritance chain illegal for $(o.filename)"
            end
        end
    end

    # now for the prefixes
    # TODO what do we do if the object is self signed?
    if !o.object.selfsigned
        certStackOffset_v6 = certStackOffset_v4 = 1
        if isempty(o.object.resources_v6) 
            if isnothing(o.object.inherit_v6_prefixes)
                #@warn "v6 prefixes empty, but inherit bool is not set.."
                #@error "empty v6 prefixes undefined inheritance? $(o.filename)"
            elseif !(o.object.inherit_v6_prefixes)
                @error "empty v6 prefixes and no inheritance? $(o.filename)"
                remark_resourceIssue!(o, "No IPv6 prefixes and no inherit flag set")
            end
        else
            while tpi.certStack[end-certStackOffset_v6].inherit_v6_prefixes
                @assert length(tpi.certStack[end-certStackOffset_v6].resources_v6) == 0
                #@debug "parent says inherit_prefixes, increasing offset to $(certStackOffset+1)"
                certStackOffset_v6 += 1
            end
        end
        if isempty(o.object.resources_v4) 
            if isnothing(o.object.inherit_v4_prefixes)
                #@warn "v4 prefixes empty, but inherit bool is not set.."
                #@error "empty v4 prefixes undefined inheritance? $(o.filename)"
            elseif !(o.object.inherit_v4_prefixes)
                @error "empty v4 prefixes and no inheritance? $(o.filename)"
                remark_resourceIssue!(o, "No IPv4 prefixes and no inherit flag set")
            end
        else
            while tpi.certStack[end-certStackOffset_v4].inherit_v4_prefixes
                @assert length(tpi.certStack[end-certStackOffset_v4].resources_v4) == 0
                #@debug "parent says inherit_prefixes, increasing offset to $(certStackOffset+1)"
                certStackOffset_v4 += 1
            end
        end
        
        # IPv6:
		check_coverage(tpi.certStack[end-certStackOffset_v6].resources_v6, o.object.resources_v6) do invalid
            @warn "illegal IP resource $(IPRange(invalid.first, invalid.last)) on $(o.filename)"
            remark_resourceIssue!(o, "Illegal IPv6 resource $(IPRange(invalid.first, invalid.last))")
            o.object.resources_valid = false
        end

        # IPv4:
        check_coverage(tpi.certStack[end-certStackOffset_v4].resources_v4, o.object.resources_v4) do invalid
            @warn "illegal IP resource $(IPRange(invalid.first, invalid.last)) on $(o.filename)"
            remark_resourceIssue!(o, "Illegal IPv4 resource $(IPRange(invalid.first, invalid.last))")
            o.object.resources_valid = false
        end
    end

end


end # module
