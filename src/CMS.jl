module CMS
using ...JDR.Common
using ..RPKI
using ..ASN
using ..DER
using SHA

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


@check "eContent" begin
    tagis_contextspecific(node, 0x00)
    # optional second pass on the EXPLICIT OCTETSTRING:
    # if the manifest is BER encoded (instead of DER), the encapsulated ASN1
    # nodes have already been parsed
    # in case of BER, the 'first' OCTETSTRING has indef length
    if ! node[1].tag.len_indef
        DER.parse_append!(DER.Buf(node[1].tag.value), node[1])
    else
        # already parsed, but can we spot the chunked OCTETSTRING case?
        if length(node[1].children) > 1
            warn!(node[1], "chunked OCTETSTRINGs ? TODO doublecheck me")
            #@debug "found multiple children in node[1]"
            concatted = collect(Iterators.flatten([n.tag.value for n in node[1].children]))
            buf = DER.Buf(concatted)
            DER.parse_replace_children!(buf, node[1])
        end

    end
    # now, be flexible: for BER mft's, there will be another OCTETSTRING
    # either way, the eContent only has 1 child
     
    checkchildren(node[1], 1)
    eContent = if node[1,1].tag isa Tag{ASN.OCTETSTRING} 
        warn!(node[1,1], "nested OCTETSTRING, BER instead of DER")
        # we need to do a second pass on this then
        DER.parse_append!(DER.Buf(node[1,1].tag.value), node[1,1])
        node[1,1,1]
    elseif node[1,1].tag isa Tag{ASN.SEQUENCE}
        node[1,1]
    else
        @error("unexpected tag $(tagtype(node[1,1])) in $(o.filename)")
        err!(node[1,1], "unexpected tag $(tagtype(node[1,1]))")
        return
    end
    tpi.eContent = eContent
end

@check "eContentType" begin
    # this can only be either a manifest or a ROA, so:
    if o.object isa MFT
        tag_OID(node, @oid("1.2.840.113549.1.9.16.1.26"))
        if tpi.setNicenames
            node.nicename *= " (MFT)"
        end
    elseif o.object isa ROA
        tag_OID(node, @oid("1.2.840.113549.1.9.16.1.24"))
        if tpi.setNicenames
            node.nicename *= " (ROA)"
        end
    else
        err!(node, "unexpected OID for this file")
    end
end
@check "encapContentInfo" begin
	# EncapsulatedContentInfo ::= SEQUENCE {
	#  eContentType ContentType,
	#  eContent [0] EXPLICIT OCTET STRING OPTIONAL }

	tagisa(node, ASN.SEQUENCE)    
	checkchildren(node, 2)
    check_ASN1_eContentType(o, node[1], tpi)
    check_ASN1_eContent(o, node[2], tpi)
end

@check "certificates" begin
    tagis_contextspecific(node, 0x00)
    if length(node[1].children) > 3
        @info "More than one certificate in $(o.filename)?"
    end
    RPKI.X509.check_ASN1_tbsCertificate(o, node[1,1], tpi)
    tpi.eeSig = node[1,3]
end

@check "sid" begin
    tagis_contextspecific(node, 0x0)
    tpi.signerIdentifier = node.tag.value

    #TODO, do we check here on tpi.subjectKeyIdentifier == tpi.signerIdentifier
    #if node[2].tag.value != tpi.subjectKeyIdentifier
    #    err!(node[2], "SignerIdentifier does not match SubjectKeyIdentifier")
    #end
end

@check "sa_contentType" begin
    tagisa(node, ASN.SET)
    tagisa(node[1], ASN.OID)
    if o.object isa ROA
        tag_OID(node[1], @oid("1.2.840.113549.1.9.16.1.24"))
        if tpi.setNicenames
            node[1].nicename = "routeOriginAuthz"
        end
    elseif o.object isa MFT
        tag_OID(node[1], @oid("1.2.840.113549.1.9.16.1.26"))
        if tpi.setNicenames
            node[1].nicename = "rpkiManifest"
        end
    end
end

@check "messageDigest" begin
    tagisa(node, ASN.SET)
end

@check "signingTime" begin
end

@check "attribute" begin
    tagisa(node, ASN.SEQUENCE)
    tagisa(node[1], ASN.OID)
    if node[1].tag.value == @oid("1.2.840.113549.1.9.3")
        check_ASN1_sa_contentType(o, node[2], tpi)
    elseif node[1].tag.value == @oid("1.2.840.113549.1.9.4")
        check_ASN1_messageDigest(o, node[2], tpi)
    elseif node[1].tag.value == @oid("1.2.840.113549.1.9.5")
        check_ASN1_signingTime(o, node[2], tpi)
    else
        @warn "unknown signedAttribute in $(o.filename)"
    end
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

    # now hash the signedAttrs for the signature check later on
    sa_raw = read(o.filename, node.tag.offset_in_file - 1 + node.tag.len + 2 )[node.tag.offset_in_file:end]

    # the hash is calculated based on the DER EXPLICIT SET OF tag, not the
    # IMPLICIT [0], so we overwrite the first byte:
    sa_raw[1] = 0x11 | 0b00100000
    tpi.saHash = bytes2hex(sha256(sa_raw))
end

@check "signatureAlgorithm" begin
    # copied from X509.jl "algorithm"
    tagisa(node, ASN.SEQUENCE)
    # FIXME: RFC6485 is not quite clear on which OID we should expect here..
    tag_OID(node[1], @oid "1.2.840.113549.1.1.1")
    tagisa(node[2], ASN.NULL)
end

@check "signature" begin
    # Decrypt signature using the EE certificate in the ROA 
    v = powermod(to_bigint(node.tag.value), ASN.value(tpi.ee_rsaExponent.tag), to_bigint(tpi.ee_rsaModulus.tag.value[2:end]))
    v.size = 4
    v_str = string(v, base=16, pad=64)
    if tpi.saHash == v_str
        node.validated = true
    else
        @error "invalid signature for $(o.filename)"
        err!(o, "Signature invalid")
        push!(tpi.lookup.invalid_signatures, o)
    end
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
    check_ASN1_signature(o, node[6], tpi)
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
