module Crl

using ...Common
using ...RPKI
using ...ASN1

using ...RPKICommon
using ...PKIX

export CRL, check_ASN1

struct CRL 
    revoked_serials::Vector{Integer}
end
CRL() = CRL([])

function check_revokedCertificates(o::RPKIObject{CRL}, node::Node) 
#        revokedCertificates     SEQUENCE OF SEQUENCE  {
#             userCertificate         CertificateSerialNumber,
#             revocationDate          Time,
#             crlEntryExtensions      Extensions OPTIONAL
#                                      -- if present, version MUST be v2
#                                  }  OPTIONAL,

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

function check_nextUpdate(o::RPKIObject{CRL}, node::Node) 
    tagisa(node, [ASN1.UTCTIME, ASN1.GENTIME])
end

function check_thisUpdate(o::RPKIObject{CRL}, node::Node) 
    tagisa(node, [ASN1.UTCTIME, ASN1.GENTIME])
end

function check_issuer(o::RPKIObject{CRL}, node::Node) 
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

function check_signature(o::RPKIObject{CRL}, node::Node) 
    # SEQ / OID / NULL
    tagisa(node, ASN1.SEQUENCE)

    tag_OID(node[1], @oid "1.2.840.113549.1.1.11")
    #TODO D-R-Y with MFT.jl and ROA.jl
    #TODO double check whether 4055 mentions CRLs specifically
    if length(node.children) == 2 
        tagisa(node[2], ASN1.NULL)
        info!(node[2], "this NULL SHOULD be absent (RFC4055)")
    end
end

function check_tbsCertList(o::RPKIObject{CRL}, node::Node)
    tagisa(node, ASN1.SEQUENCE)
    # version, optional
    # if present, MUST be v2 == 0x01
    offset = 0
    if node[1].tag isa Tag{ASN1.INTEGER}
        offset += 1
        tagvalue(node[1], ASN1.INTEGER, 0x1)
    end

    # signature
    signature = node[offset+1]
    check_signature(o, signature)

    # issuer
    issuer = node[offset+2]
    check_issuer(o, issuer)

    # thisUpdate
    thisUpdate = node[offset+3]
    check_thisUpdate(o, thisUpdate)

    # optional nextUpdate
    if node[offset+4].tag isa Tag{ASN1.UTCTIME} ||
        node[offset+4].tag isa Tag{ASN1.GENTIME}
        check_nextUpdate(o, node[offset+4])
        offset += 1
    end

    # optional revokedCertificates and crlExtensions
    if length(node.children) > offset
        if node[offset+4].tag isa Tag{ASN1.SEQUENCE}
            revokedCertificates = node[offset+4]
            check_revokedCertificates(o, revokedCertificates)
            offset += 1
        else
            # TODO crlExtensions
        end
    end
    if length(node.children) > offset
        # now it can only be the crlExtensions    
        tagis_contextspecific(node[offset+4], 0x00)
    end
end

import .RPKI:check_ASN1
function check_ASN1(o::RPKIObject{CRL}, tpi::TmpParseInfo) :: RPKIObject{CRL}
    # The certificate should consist of three parts: (RFC5280)
	# Certificate  ::=  SEQUENCE  {
	#      tbsCertificate       TBSCertificate,
	#      signatureAlgorithm   AlgorithmIdentifier,
	#      signature            BIT STRING  }
    
    childcount(o.tree, 3)
    tbsCertList = o.tree.children[1]
    check_tbsCertList(o, tbsCertList)

    
    o
end


#function check_signature(o::RPKIObject{CRL}, parent::RPKINode, lookup::RPKI.Lookup) :: RPKIObject{CRL}
#    @warn "in check_signature for CRL, not implemented yet" maxlog=5
#    o
#end

end # module
