module CMS
using JDR.Common: @oid, oid_to_str, remark_ASN1Issue!, remark_ASN1Error!, remark_encodingIssue!, remark_validityIssue!
using JDR.RPKICommon: RPKIObject, ROA, MFT, TmpParseInfo
using JDR.ASN1: check_tag, check_OID, check_value, childcount, check_contextspecific
using JDR.ASN1: istag, to_bigint
using JDR.ASN1: ASN1 # for ASN1 tags
using JDR.ASN1.DER: Buf, parse_append!, parse_replace_children!
using JDR.RPKICommon: RPKIFile # for macro_check
using ..X509: X509 # to check TbsCert

using SHA: sha256

include("../ASN1/macro_check.jl")

@check "contentType" begin
    check_OID(node, @oid("1.2.840.113549.1.7.2"))
end

@check "version"  begin
    check_value(node, ASN1.INTEGER, 0x03)
end

@check "digestAlgorithm" begin
    check_tag(node, ASN1.SEQUENCE)
    check_OID(node[1], @oid("2.16.840.1.101.3.4.2.1")) # SHA-256 RFC5754 sec 2.2
    if tpi.nicenames
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
    check_contextspecific(node, 0x00)
    # optional second pass on the EXPLICIT OCTETSTRING:
    # if the manifest is BER encoded (instead of DER), the encapsulated ASN1
    # nodes have already been parsed
    # in case of BER, the 'first' OCTETSTRING has indef length
    if ! node[1].tag.len_indef
        tpi.cms_message_digest = bytes2hex(sha256(node[1].tag.value))
        parse_append!(Buf(node[1].tag.value), node[1])
    else
        # already parsed, but can we spot the chunked OCTETSTRING case?
        if length(node[1].children) > 1
            remark_encodingIssue!(node[1], "fragmented OCTETSTRING, CER instead of DER?")
            #@debug "found multiple children in node[1]"
            concatted = collect(Iterators.flatten([n.tag.value for n in node[1].children]))
            buf = Buf(concatted)
            tpi.cms_message_digest = bytes2hex(sha256(concatted))
            parse_replace_children!(buf, node[1])
        else
            tpi.cms_message_digest = ""
        end

    end
    # now, be flexible: for BER mft's, there will be another OCTETSTRING
    # either way, the eContent only has 1 child
     
    childcount(node[1], 1)
    eContent = if istag(node[1,1].tag, ASN1.OCTETSTRING)
        remark_encodingIssue!(node[1,1], "nested OCTETSTRING, BER instead of DER")
        # we need to do a second pass on this then
        parse_append!(Buf(node[1,1].tag.value), node[1,1])
        node[1,1,1]
    elseif istag(node[1,1].tag, ASN1.SEQUENCE)
        node[1,1]
    else
        @error("unexpected tag $(node[1,1].tag.number) in $(o.filename)")
        remark_ASN1Error!(node[1,1], "unexpected tag $(node[1,1].tag.number)")
        return
    end
    tpi.eContent = eContent
end

@check "eContentType" begin
    # this can only be either a manifest or a ROA, so:
    if o.object isa MFT
        check_OID(node, @oid("1.2.840.113549.1.9.16.1.26"))
        if tpi.nicenames
            node.nicename *= " (MFT)"
        end
    elseif o.object isa ROA
        check_OID(node, @oid("1.2.840.113549.1.9.16.1.24"))
        if tpi.nicenames
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
    check_contextspecific(node, 0x00)
    if length(node[1].children) > 3
        @info "More than one certificate in $(o.filename)?"
    end
    X509.check_ASN1_tbsCertificate(o, node[1,1], tpi)
    X509.check_ASN1_signatureAlgorithm(o, node[1,2], tpi)
    X509.check_ASN1_signatureValue(o, node[1,3], tpi)
    tpi.eeSig = node[1,3]
end

@check "sid" begin
    check_contextspecific(node, 0x00)
    signerIdentifier = node.tag.value

    if tpi.ee_ski != signerIdentifier
        @warn "unexpected signerIdentifier in $(o.filename)"
        remark_ASN1Error!(node, "signerIdentifier mismatch, expected
                          $(bytes2hex(tpi.ee_ski))")
    end
end

@check "sa_contentType" begin
    check_tag(node, ASN1.SET)
    check_tag(node[1], ASN1.OID)
    if o.object isa ROA
        check_OID(node[1], @oid("1.2.840.113549.1.9.16.1.24"))
        if tpi.nicenames
            node[1].nicename = "routeOriginAuthz"
        end
    elseif o.object isa MFT
        check_OID(node[1], @oid("1.2.840.113549.1.9.16.1.26"))
        if tpi.nicenames
            node[1].nicename = "rpkiManifest"
        end
    end
end

@check "messageDigest" begin
    check_tag(node, ASN1.SET)
    md = bytes2hex(node[1].tag.value)

    o.cms_digest_valid = if tpi.cms_message_digest == ""
        _ec_offset = tpi.eContent.tag.offset_in_file
        _ec_len = tpi.eContent.tag.len + tpi.eContent.tag.headerlen
        ec_raw = @view o.tree.buf.data[_ec_offset:_ec_offset+_ec_len-1]
        md == bytes2hex(sha256(ec_raw))
    else
        md == tpi.cms_message_digest
    end
    if !o.cms_digest_valid
        remark_ASN1Error!(o, "CMS Digest incorrect")
        @error "Incorrect CMS digest for $(o.filename)"
    end
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
    check_contextspecific(node, 0x00)
    # store a pointer to the signedAttrs, so we can do specific checks in
    # MFT/ROA.jl
    tpi.signedAttrs = node
    # IMPLICIT SET OF Attributes (1..MAX)
    for attr in node.children
        (@__MODULE__).check_ASN1_attribute(o, attr, tpi)
    end
    # RFC6488: MUST include the content-type and message-digest attributes

    # now hash the signedAttrs for the signature check later on
    sa_raw = @view o.tree.buf.data[node.tag.offset_in_file:node.tag.offset_in_file + node.tag.len + 2 - 1]

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
    v = powermod(to_bigint(node.tag.value), ASN1.value(tpi.ee_rsaExponent.tag), to_bigint(@view tpi.ee_rsaModulus.tag.value[2:end]))
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
    
    check_contextspecific(node, 0x00)
    (@__MODULE__).check_ASN1_signedData(o, node[1], tpi)
end

end # end module
