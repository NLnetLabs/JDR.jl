module Crl

using ...Common
using ...RPKI
using ...ASN1

using ...RPKICommon
using ...PKIX

using Dates
using SHA

export CRL, check_ASN1

mutable struct CRL 
    revoked_serials::Vector{Integer}
    thisUpdate::Union{Nothing, DateTime}
    nextUpdate::Union{Nothing, DateTime}
end
CRL() = CRL([], nothing, nothing)
Base.show(io::IO, crl::CRL) = print(io, crl.thisUpdate, " -> ", crl.nextUpdate, "\n", crl.revoked_serials)

import ...PKIX.@check


@check "version" begin
    tagvalue(node, ASN1.INTEGER, 0x1)
end
@check "signature" begin
    tagisa(node, ASN1.SEQUENCE)
    tag_OID(node[1], @oid "1.2.840.113549.1.1.11")
    #TODO double check whether 4055 mentions CRLs specifically
    if length(node.children) == 2 
        tagisa(node[2], ASN1.NULL)
        #FIXME #info!(node[2], "this NULL SHOULD be absent (RFC4055)")
    end
end
@check "issuer" begin
    tagisa(node, ASN1.SEQUENCE)
    tagisa(node[1], ASN1.SET)
        # it's a SET of AttributeTypeAndValue 
        # which is a SEQUENCE of type (OID) + value (ANY)
        # from RFC6487:
		# An issuer name MUST contain one instance of the CommonName attribute
		#   and MAY contain one instance of the serialNumber attribute.  If both
		#   attributes are present, it is RECOMMENDED that they appear as a set.
		#   The CommonName attribute MUST be encoded using the ASN1.1 type
		#   PrintableString [X.680].

    childcount(node[1], 1:2)
    # If the issuer contains the serialNumber as well,
    # the set should contain 1 child, the RECOMMENDED set
    # TODO check this interpretation
    containAttributeTypeAndValue(node[1], @oid("2.5.4.3"), ASN1.PRINTABLESTRING, [ASN1.UTF8STRING])
end
@check "thisUpdate" begin
    tagisa(node, [ASN1.UTCTIME, ASN1.GENTIME])
    o.object.thisUpdate = ASN1.value(node.tag)
end
@check "nextUpdate" begin
    tagisa(node, [ASN1.UTCTIME, ASN1.GENTIME])
    o.object.nextUpdate = ASN1.value(node.tag)
end

@check "revokedCertificates" begin
    tagisa(node, ASN1.SEQUENCE)
    if !isnothing(node.children)
        for s in node.children
            tagisa(s, ASN1.SEQUENCE)

            # userCertificate serialnumber
            tagisa(s[1], ASN1.INTEGER)
            push!(o.object.revoked_serials, ASN1.value(s[1].tag, force_reinterpret=true))

            # recovationDate Time
            tagisa(s[2], [ASN1.UTCTIME, ASN1.GENTIME])
        end
    else
        @debug "empty revokedCertificates SEQUENCE in $(o.filename)"
    end
end

const MANDATORY_EXTENSIONS = Vector{Pair{Vector{UInt8}, String}}([
                                                    @oid("2.5.29.35") => "authorityKeyIdentifier",
                                                    @oid("2.5.29.20") =>  "cRLNumber",
                                                   ])

@check "authorityKeyIdentifier" begin
    tagisa(node, ASN1.OCTETSTRING)
    # Need a second pass to decode the OCTETSTRING
    DER.parse_append!(DER.Buf(node.tag.value), node)
end

@check "cRLNumber" begin
end

function check_ASN1_extension(oid::Vector{UInt8}, o::RPKIObject{T}, node::Node, tpi::TmpParseInfo) where T
    if oid == @oid("2.5.29.35")
        check_ASN1_authorityKeyIdentifier(o, node, tpi)
    elseif oid == @oid("2.5.29.20")
        check_ASN1_cRLNumber(o, node, tpi)
    else
        @warn "Unknown oid $(oid) passed to CRL::check_extension" maxlog=10
        remark_ASN1Issue!(node, "Unknown extension")
    end
end
@check "crlExtensions" begin
    tagis_contextspecific(node, 0x00)
    check_extensions(node, (@__MODULE__).MANDATORY_EXTENSIONS)
end

@check "tbsCertList" begin
#   TBSCertList  ::=  SEQUENCE  {
#        version                 Version OPTIONAL,
#                                     -- if present, MUST be v2
#        signature               AlgorithmIdentifier,
#        issuer                  Name,
#        thisUpdate              Time,
#        nextUpdate              Time OPTIONAL,
#        revokedCertificates     SEQUENCE OF SEQUENCE  {
#             userCertificate         CertificateSerialNumber,
#             revocationDate          Time,
#             crlEntryExtensions      Extensions OPTIONAL
#                                      -- if present, version MUST be v2
#                                  }  OPTIONAL,
#        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
#                                      -- if present, version MUST be v2
#                                  }
    tagisa(node, ASN1.SEQUENCE)
    # version, optional
    # if present, MUST be v2 == 0x01
    offset = 0
    if node[1].tag isa Tag{ASN1.INTEGER}
        offset += 1
        (@__MODULE__).check_ASN1_version(o, node[1], tpi)
    end
    
    (@__MODULE__).check_ASN1_signature(o, node[offset + 1], tpi)
    (@__MODULE__).check_ASN1_issuer(o, node[offset + 2], tpi)
    (@__MODULE__).check_ASN1_thisUpdate(o, node[offset + 3], tpi)
    
    # nextUpdate is optional
    if node[offset+4].tag isa Tag{ASN1.UTCTIME} ||
        node[offset+4].tag isa Tag{ASN1.GENTIME}
        (@__MODULE__).check_ASN1_nextUpdate(o, node[offset + 4], tpi)
        offset += 1
    end
    # optional revokedCertificates
    if node[offset+4].tag isa Tag{ASN1.SEQUENCE}
        (@__MODULE__).check_ASN1_revokedCertificates(o, node[offset + 4], tpi)
        offset += 1
    end

    # optional crlExtensions
    if length(node.children) > offset
        (@__MODULE__).check_ASN1_crlExtensions(o, node[offset + 4], tpi)
    end
end


import .RPKI:check_ASN1
function check_ASN1(o::RPKIObject{CRL}, tpi::TmpParseInfo) :: RPKIObject{CRL}
	# CertificateList  ::=  SEQUENCE  {
	#  tbsCertList          TBSCertList,
	#  signatureAlgorithm   AlgorithmIdentifier,
	#  signatureValue       BIT STRING  }
    
    childcount(o.tree, 3)

    check_ASN1_tbsCertList(o, o.tree.children[1], tpi)

    o
end

import .RPKI:check_cert
function check_cert(o::RPKIObject{CRL}, tpi::TmpParseInfo) :: RPKI.RPKIObject{CRL}
    sig = o.tree.children[3]
    signature = to_bigint(sig.tag.value[2:end])
    v = powermod(signature, tpi.certStack[end].rsa_exp, tpi.certStack[end].rsa_modulus)
    v.size = 4
    v_str = string(v, base=16, pad=64)

    tbs_raw = read(o.filename, o.tree[2].tag.offset_in_file-1)[o.tree[1].tag.offset_in_file:end]
    my_hash = bytes2hex(sha256(tbs_raw))

    # compare hashes
    if v_str == my_hash
        o.sig_valid = true
    else
        remark_validityIssue!(o, "invalid signature")
        o.sig_valid = false
    end
    
    o
end


end # module
