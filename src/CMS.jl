module CMS
using ...JDR.Common
using ..RPKI
using ..ASN

macro check(name, block)
    fnname = Symbol("check_ASN1_$(name)")
    :(
      function $fnname(o::RPKIObject{T}, node::Node, tpi::TmpParseInfo) where T
          if tpi.setNicenames
              node.nicename = $name
          end
          $block
      end
     )
end

@check "contentType" begin
    tag_OID(node, @oid("1.2.840.113549.1.7.2"))
end

@check "version"  begin
    tagvalue(node, ASN.INTEGER, 0x03)
end

@check "digestAlgorithms" begin
    tagisa(node, ASN.SET)
    checkchildren(node, 1)
    tagisa(node[1], ASN.SEQUENCE)
    tag_OID(node[1,1], @oid("2.16.840.1.101.3.4.2.1"))
    # TODO: This field MUST contain the same algorithm identifier as the
    #    signature field in the sequence tbsCertificate (Section 4.1.2.3).

    if length(node[1].children) == 2
        tagisa(node[1,2], ASN.NULL)
        info!(node[1,2], "this NULL SHOULD be absent (RFC4055)")
    end
end


@check "encapContentInfo" begin
	# EncapsulatedContentInfo ::= SEQUENCE {
	#  eContentType ContentType,
	#  eContent [0] EXPLICIT OCTET STRING OPTIONAL }

	tagisa(node, ASN.SEQUENCE)    
	checkchildren(node, 2)

    tpi.eContent = node[2]
end

@check "certificates" begin
    tagis_contextspecific(node, 0x00)
    if length(node[1].children) > 3
        @info "More than one certificate in $(o.filename)?"
    end
    RPKI.X509.check_ASN1_tbsCertificate(o, node[1,1], tpi)
end

@check "signerInfos" begin
end

@check "signedData" begin
	# SignedData ::= SEQUENCE {
	#   version CMSVersion,
	#   digestAlgorithms DigestAlgorithmIdentifiers,
	#   encapContentInfo EncapsulatedContentInfo,
	#   certificates [0] IMPLICIT CertificateSet OPTIONAL,
	#   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
	#   signerInfos SignerInfos }

    # Signed-Data as defined in RFC 5652 (CMS) can contain up to 6 children but
    # for RPKI Manifests, we MUST have the CertificateSet and MUST NOT have the
    # RevocationInfoChoices

    tagisa(node, ASN.SEQUENCE)
    checkchildren(node, 5)

    check_ASN1_version(o, node[1], tpi)
    check_ASN1_digestAlgorithms(o, node[2], tpi)
    check_ASN1_encapContentInfo(o, node[3], tpi)
    # eContent specific checks happen in MFT.jl or ROA.jl via the TmpParseInfo
    check_ASN1_certificates(o, node[4], tpi)
    check_ASN1_signerInfos(o, node[5], tpi)


end

@check "content" begin
    tagis_contextspecific(node, 0x0)
	 
    check_ASN1_signedData(o, node[1], tpi)
end

end # end module
