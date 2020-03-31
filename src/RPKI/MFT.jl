struct MFT
    files::Vector{String}
end
MFT() = MFT([])

import Base.length
length(::Nothing) = 0
function check_signed_data(o::RPKIObject{MFT}, sd::Node) :: RPKIObject{MFT}
    # Signed-Data as defined in RFC 5652 (CMS) can contain up to 6 children
    # but for RPKI Manifests, we MUST have the CertificateSet and MUST NOT have
    # the RevocationInfoChoices
    checkchildren(sd, 5)

    # CMSVersion
    tagvalue(sd[1], ASN.INTEGER, 0x03)

    # DigestAlgorithmIdentifiers
    tagisa(sd[2], ASN.SET) 
    tagisa(sd[2,1], ASN.SEQUENCE)
    tag_OID(sd[2,1,1], @oid "2.16.840.1.101.3.4.2.1")
    # TODO: This field MUST contain the same algorithm identifier as the
    #    signature field in the sequence tbsCertificate (Section 4.1.2.3).
    
    if length(sd[2,1].children) == 2 
        tagisa(sd[2,1,2], ASN.NULL)
        remark!(sd[2,1,2], "this NULL SHOULD be absent (RFC4055)")
    end

    # EncapsulatedContentInfo
    tagisa(sd[3], ASN.SEQUENCE)
    eContentType = sd[3,1]
    eContent = sd[3,2]

    tag_OID(eContentType, @oid "1.2.840.113549.1.9.16.1.26")
    tagis_contextspecific(eContent, 0x00)
    tagisa(eContent[1], ASN.OCTETSTRING)

    # if the OCTETSTRING is of indefinite length (BER instead of proper DER), we
    # already have the encapsulated ASN nodes parsed
    # if the OCTETSTRING is of definite length (like it should be), we need to
    # to a second pass on the contents of it
    if ! eContent[1].tag.len_indef
        DER.parse_append!(DER.Buf(eContent[1].tag.value), eContent[1])
    else
        # already parsed, but can we spot the chunked OCTETSTRING case?
        if length(eContent[1].children) > 1
            remark!(eContent[1], "chunked OCTETSTRINGs ? TODO doublecheck me")
            #@debug "found multiple children in eContent[1]"
            concatted = collect(Iterators.flatten([n.tag.value for n in eContent[1].children]))
            buf = DER.Buf(concatted)
            DER.parse_replace_children!(buf, eContent[1])
        end

    end

    # now, be flexible: for BER mft's, there will be another OCTETSTRING
    # either way, the eContent only has 1 child
     
    checkchildren(eContent[1], 1)
    manifest = if eContent[1,1].tag isa Tag{ASN.OCTETSTRING} #TODO make a function for this
        remark!(eContent[1,1], "nested OCTETSTRING, BER instead of DER")
        # we need to do a second pass on this then
        DER.parse_append!(DER.Buf(eContent[1,1].tag.value), eContent[1,1])
        eContent[1,1,1]
    elseif eContent[1,1].tag isa Tag{ASN.SEQUENCE}
        eContent[1,1]
    else
        remark!(eContent[1,1], "unexpected tag $(tagtype(eContent[1,1]))")
        return o
    end
    o = check_manifest(o, manifest)

    # CertificateSet, optional [0] (IMPLICITly tagged), MUST be here
    tagis_contextspecific(sd[4], 0x00)

    # SignerInfos
    signerinfos = sd[5]
    o = check_signerinfo(o, signerinfos)

    o
end

function check_signerinfo(o::RPKIObject{MFT}, sis::Node) :: RPKIObject{MFT}
    tagisa(sis, ASN.SET)

    # SignerInfos MUST only contain a single SignerInfo object 
    checkchildren(sis, 1)
    # a SignerInfo is a SEQUENCE
    si = sis[1]
    tagisa(si, ASN.SEQUENCE)

    # CMSVersion, MUST be 3
    tagvalue(si[1], ASN.INTEGER, 0x03)

    # SignerIdentifier
    # RFC 6488:
    #   For RPKI signed objects, the sid MUST be the SubjectKeyIdentifier
    #   that appears in the EE certificate carried in the CMS certificates
    #   field.

    # thus: SubjectKeyIdentifier
    tagis_contextspecific(si[2], 0x00)

    # DigestAlgorithmIdentifier
    #
    #
    tagisa(si[3], ASN.SEQUENCE)
    tag_OID(si[3, 1], @oid "2.16.840.1.101.3.4.2.1")

    if length(si[3,1].children) == 2 
        tagisa(si[3,1,2], ASN.NULL)
        remark!(si[3,1,2], "this NULL SHOULD be absent (RFC4055)")
    end
    #tagisa(si[3, 2], ASN.NULL)

    # SignedAttributes
    # MUST be present
    # MUST include 'content-type' and 'message-digest' 
    # MAY include 'signing-time' and/or 'binary-signing-time'
    checkchildren(si[4], 2:4)
    # TODO how to check for optional Type/Values ?
    # we can not attach them to the Object and rely on them later in the
    # process, as they might not be present in the .mft

    # content-type
    containAttributeTypeAndValue(si[4], @oid("1.2.840.113549.1.9.3"), ASN.SET)
    # TODO:
    # must contain 1.2.840.113549.1.9.16.1.26 (rpkiManifest)

    # message-digest
    containAttributeTypeAndValue(si[4], @oid("1.2.840.113549.1.9.4"), ASN.SET)

    # SignatureAlgorithmIdentifier
    tagisa(si[5], ASN.SEQUENCE)
    tag_OID(si[5, 1], @oid "1.2.840.113549.1.1.1")
    tagisa(si[5, 2], ASN.NULL)

    # SignatureValue
    tagisa(si[6], ASN.OCTETSTRING)
    if si[6].tag.len != 256
        remark!(si[6], "expected 256 bytes instead of $(si[6].tag.len)")
    end
    
    o
end

function check_manifest(o::RPKIObject{MFT}, m::Node) :: RPKIObject{MFT}
    #RFC 6486
    tagisa(m, ASN.SEQUENCE)
    checkchildren(m, 5:6)
    # the 'version' is optional, defaults to 0
    offset = 0
    if length(m.children) == 6
        offset = 1
        # version:
        tagis_contextspecific(m[1], 0x00)
        # EXPLICIT tagging, so the version must be in a child
        checkchildren(m[1], 1)
        tagisa(m[1, 1], ASN.INTEGER)
        if value(m[1, 1].tag) == 0
            remark!(m[1, 1], "version explicitly set to 0 while that is the default")
        end
    end

    # manifestNumber
    tagisa(m[offset+1], ASN.INTEGER)

    # TODO: attach these to the RPKIObject.object ?
    # thisUpdate
    tagisa(m[offset+2], ASN.GENTIME) 
    # nextUpdate
    tagisa(m[offset+3], ASN.GENTIME) 

    # fileHashAlg
    tag_OID(m[offset+4], @oid "2.16.840.1.101.3.4.2.1")

    # fileList
    filelist = m[offset+5]
    tagisa(filelist, ASN.SEQUENCE)
    for file_and_hash in filelist.children
        tagisa(file_and_hash, ASN.SEQUENCE)
        tagisa(file_and_hash[1], ASN.IA5STRING)
        tagisa(file_and_hash[2], ASN.BITSTRING)
        #@debug file_and_hash[2]
        push!(o.object.files, value(file_and_hash[1].tag))
    end

    o
end

function check(o::RPKIObject{MFT}) :: RPKIObject{MFT}
    cmsobject = o.tree
    # CMS, RFC5652
    tagisa(o.tree, ASN.SEQUENCE)
    tag_OID(o.tree[1], @oid "1.2.840.113549.1.7.2") # contentType
    tagis_contextspecific(o.tree[2], 0x00) # content

    # 6488:
    tagisa(o.tree[2, 1], ASN.SEQUENCE)
    o = check_signed_data(o, o.tree[2, 1])
    
    o
end

