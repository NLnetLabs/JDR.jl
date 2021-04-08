module CMS
using ...JDR.Common
using ...JDR.RPKICommon
using ...ASN1
using ..X509

import ...PKIX.@check

@check "contentType" begin
    check_OID(node, @oid("1.2.840.113549.1.7.2"))
end

@check "version"  begin
    check_value(node, ASN1.INTEGER, 0x03)
end

@check "digestAlgorithm" begin
    check_tag(node, ASN1.SEQUENCE)
    check_OID(node[1], @oid("2.16.840.1.101.3.4.2.1")) # SHA-256 RFC5754 sec 2.2
    if tpi.setNicenames
        node[1].nicevalue = oid_to_str(node[1].tag.value)
    end
    # TODO: This field MUST contain the same algorithm identifier as the
    #    signature field in the sequence tbsCertificate (Section 4.1.2.3).

    if length(node.children) == 2
        check_tag(node[2], ASN1.NULL)
        remark_ASN1Issue!(node[2], "parameters MUST be absent (RFC5754)")
    end
end

@check "digestAlgorithms" begin
    check_tag(node, ASN1.SET)
    childcount(node, 1)
    (@__MODULE__).check_ASN1_digestAlgorithm(o, node[1], tpi)
end


@check "eContent" begin
    check_contextspecific(node, ASN1.RESERVED_ENC)
    # optional second pass on the EXPLICIT OCTETSTRING:
    # if the manifest is BER encoded (instead of DER), the encapsulated ASN1
    # nodes have already been parsed
    # in case of BER, the 'first' OCTETSTRING has indef length
    if ! node[1].tag.len_indef
        DER.parse_append!(DER.Buf(node[1].tag.value), node[1])
    else
        # already parsed, but can we spot the chunked OCTETSTRING case?
        if length(node[1].children) > 1
            remark_encodingIssue!(node[1], "fragmented OCTETSTRING, CER instead of DER?")
            #@debug "found multiple children in node[1]"
            concatted = collect(Iterators.flatten([n.tag.value for n in node[1].children]))
            buf = DER.Buf(concatted)
            DER.parse_replace_children!(buf, node[1])
        end

    end
    # now, be flexible: for BER mft's, there will be another OCTETSTRING
    # either way, the eContent only has 1 child
     
    childcount(node[1], 1)
    eContent = if istag(node[1,1].tag, ASN1.OCTETSTRING)
        remark_encodingIssue!(node[1,1], "nested OCTETSTRING, BER instead of DER")
        # we need to do a second pass on this then
        DER.parse_append!(DER.Buf(node[1,1].tag.value), node[1,1])
        node[1,1,1]
    elseif istag(node[1,1].tag, ASN1.SEQUENCE)
        node[1,1]
    else
        @error("unexpected tag $(tagtype(node[1,1])) in $(o.filename)")
        remark_ASN1Error!(node[1,1], "unexpected tag $(tagtype(node[1,1]))")
        return
    end
    tpi.eContent = eContent
end

@check "eContentType" begin
    # this can only be either a manifest or a ROA, so:
    if o.object isa MFT
        check_OID(node, @oid("1.2.840.113549.1.9.16.1.26"))
        if tpi.setNicenames
            node.nicename *= " (MFT)"
        end
    elseif o.object isa ROA
        check_OID(node, @oid("1.2.840.113549.1.9.16.1.24"))
        if tpi.setNicenames
            node.nicename *= " (ROA)"
        end
    else
        remark_ASN1Error!(node[1,1], "unexpected OID for this filetype")
    end
end
@check "encapContentInfo" begin
	# EncapsulatedContentInfo ::= SEQUENCE {
	#  eContentType ContentType,
	#  eContent [0] EXPLICIT OCTET STRING OPTIONAL }

	check_tag(node, ASN1.SEQUENCE)    
	childcount(node, 2)
    (@__MODULE__).check_ASN1_eContentType(o, node[1], tpi)
    (@__MODULE__).check_ASN1_eContent(o, node[2], tpi)
end

@check "certificates" begin
    check_contextspecific(node, ASN1.RESERVED_ENC)
    if length(node[1].children) > 3
        @info "More than one certificate in $(o.filename)?"
    end
    X509.check_ASN1_tbsCertificate(o, node[1,1], tpi)
    X509.check_ASN1_signatureAlgorithm(o, node[1,2], tpi)
    X509.check_ASN1_signatureValue(o, node[1,3], tpi)
    tpi.eeSig = node[1,3]
end

@check "sid" begin
    check_contextspecific(node, ASN1.RESERVED_ENC)
    tpi.signerIdentifier = node.tag.value

    #TODO, do we check here on tpi.subjectKeyIdentifier == tpi.signerIdentifier
    #if node[2].tag.value != tpi.subjectKeyIdentifier
    #    err!(node[2], "SignerIdentifier does not match SubjectKeyIdentifier")
    #end
end

@check "sa_contentType" begin
    check_tag(node, ASN1.SET)
    check_tag(node[1], ASN1.OID)
    if o.object isa ROA
        check_OID(node[1], @oid("1.2.840.113549.1.9.16.1.24"))
        if tpi.setNicenames
            node[1].nicename = "routeOriginAuthz"
        end
    elseif o.object isa MFT
        check_OID(node[1], @oid("1.2.840.113549.1.9.16.1.26"))
        if tpi.setNicenames
            node[1].nicename = "rpkiManifest"
        end
    end
end

@check "messageDigest" begin
    check_tag(node, ASN1.SET)
end

@check "signingTime" begin
end

@check "attribute" begin
    check_tag(node, ASN1.SEQUENCE)
    check_tag(node[1], ASN1.OID)
    if node[1].tag.value == @oid("1.2.840.113549.1.9.3")
        (@__MODULE__).check_ASN1_sa_contentType(o, node[2], tpi)
    elseif node[1].tag.value == @oid("1.2.840.113549.1.9.4")
        (@__MODULE__).check_ASN1_messageDigest(o, node[2], tpi)
    elseif node[1].tag.value == @oid("1.2.840.113549.1.9.5")
        (@__MODULE__).check_ASN1_signingTime(o, node[2], tpi)
    else
        @warn "unknown signedAttribute in $(o.filename)"
    end
end
@check "signedAttrs" begin
    check_contextspecific(node, ASN1.RESERVED_ENC)
    # store a pointer to the signedAttrs, so we can do specific checks in
    # MFT/ROA.jl
    tpi.signedAttrs = node
    # IMPLICIT SET OF Attributes (1..MAX)
    for attr in node.children
        (@__MODULE__).check_ASN1_attribute(o, attr, tpi)
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
    check_tag(node, ASN1.SEQUENCE)
    # two OIDs allowed, https://tools.ietf.org/html/rfc7935#section-7
    check_OID(node[1], [@oid("1.2.840.113549.1.1.1"), @oid("1.2.840.113549.1.1.11")])
    check_tag(node[2], ASN1.NULL) # here, the parameters MUST be present and MUST be NULL according to 3370#4.2.1
end

@check "signature" begin
    # Decrypt signature using the EE certificate in the ROA 
    v = powermod(to_bigint(node.tag.value), ASN1.value(tpi.ee_rsaExponent.tag), to_bigint(tpi.ee_rsaModulus.tag.value[2:end]))
    v.size = 4
    v_str = string(v, base=16, pad=64)
    if tpi.saHash == v_str
        node.validated = true
    else
        @error "invalid signature for $(o.filename)"
        remark_validityIssue!(o, "signature invalid")
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

    check_tag(node, ASN1.SEQUENCE)
    (@__MODULE__).check_ASN1_version(o, node[1], tpi)
    (@__MODULE__).check_ASN1_sid(o, node[2], tpi)
    (@__MODULE__).check_ASN1_digestAlgorithm(o, node[3], tpi)
    (@__MODULE__).check_ASN1_signedAttrs(o, node[4], tpi)
    (@__MODULE__).check_ASN1_signatureAlgorithm(o, node[5], tpi)
    (@__MODULE__).check_ASN1_signature(o, node[6], tpi)
end

@check "signerInfos" begin
    check_tag(node, ASN1.SET)    
    if length(node.children) > 1
        @info "More than one signerInfo in $(o.filename)"
    end
    for si in node.children
        (@__MODULE__).check_ASN1_signerInfo(o, si, tpi)
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

    check_tag(node, ASN1.SEQUENCE)
    childcount(node, 5)

    (@__MODULE__).check_ASN1_version(o, node[1], tpi)
    (@__MODULE__).check_ASN1_digestAlgorithms(o, node[2], tpi)
    (@__MODULE__).check_ASN1_encapContentInfo(o, node[3], tpi)
    # eContent specific checks happen in MFT.jl or ROA.jl via the TmpParseInfo
    (@__MODULE__).check_ASN1_certificates(o, node[4], tpi)
    (@__MODULE__).check_ASN1_signerInfos(o, node[5], tpi)

end

@check "content" begin
    check_contextspecific(node, ASN1.RESERVED_ENC)
	 
    (@__MODULE__).check_ASN1_signedData(o, node[1], tpi)
end

end # end module
