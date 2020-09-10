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

@check "digestAlgorithm" begin
    tagisa(node, ASN.SEQUENCE)
    tag_OID(node[1], @oid("2.16.840.1.101.3.4.2.1"))
    # TODO: This field MUST contain the same algorithm identifier as the
    #    signature field in the sequence tbsCertificate (Section 4.1.2.3).

    if length(node.children) == 2
        tagisa(node[2], ASN.NULL)
        info!(node[2], "this NULL SHOULD be absent (RFC4055)")
    end
end

@check "digestAlgorithms" begin
    tagisa(node, ASN.SET)
    checkchildren(node, 1)
    check_ASN1_digestAlgorithm(o, node[1], tpi)
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

@check "sid" begin
    tagis_contextspecific(node, 0x0)
    tpi.signerIdentifier = node.tag.value

    #TODO, do we check here on tpi.subjectKeyIdentifier == tpi.signerIdentifier
    #if node[2].tag.value != tpi.subjectKeyIdentifier
    #    err!(node[2], "SignerIdentifier does not match SubjectKeyIdentifier")
    #end
end

@check "attribute" begin
    tagisa(node, ASN.SEQUENCE)
end
@check "signedAttrs" begin
    tagis_contextspecific(node, 0x0)
    # store a pointer to the signedAttrs, so we can do specific checks in
    # MFT/ROA.jl
    tpi.signedAttrs = node
    # IMPLICIT SET OF Attributes (1..MAX)
    for attr in node.children
        check_ASN1_attribute(o, attr, tpi)
    end
    # RFC6488: MUST include the content-type and message-digest attributes
end

@check "signatureAlgorithm" begin
    # copied from X509.jl "algorithm"
    tagisa(node, ASN.SEQUENCE)
    # FIXME: RFC6485 is not quite clear on which OID we should expect here..
    tag_OID(node[1], @oid "1.2.840.113549.1.1.1")
    tagisa(node[2], ASN.NULL)
end

@check "signerInfo" begin
  #  SignerInfo ::= SEQUENCE {
  #	   version CMSVersion,
  #	   sid SignerIdentifier,
  #	   digestAlgorithm DigestAlgorithmIdentifier,
  #	   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
  #	   signatureAlgorithm SignatureAlgorithmIdentifier,
  #	   signature SignatureValue,
  #	   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }

    tagisa(node, ASN.SEQUENCE)
	check_ASN1_version(o, node[1], tpi)
	check_ASN1_sid(o, node[2], tpi)
	check_ASN1_digestAlgorithm(o, node[3], tpi)
    check_ASN1_signedAttrs(o, node[4], tpi)
    check_ASN1_signatureAlgorithm(o, node[5], tpi)
end

@check "signerInfos" begin
    tagisa(node, ASN.SET)    
    if length(node.children) > 1
        @info "More than one signerInfo in $(o.filename)"
    end
    for si in node.children
        check_ASN1_signerInfo(o, si, tpi)
    end
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
