struct VRP{AFI<:IPNet}
    prefix::AFI
    maxlength::Integer
end

mutable struct ROA
    asid::Integer
    vrps::Vector{VRP}
    rsa_modulus::BigInt
    rsa_exp::Int
    local_eContent_hash::String
end
ROA() = ROA(0, [], 0, 0, "EMPTY_LOCAL_HASH")

function Base.show(io::IO, roa::ROA)
    print(io, "  ASID: ", roa.asid, "\n")
    print(io, "  VRPs:\n")
    for vrp in roa.vrps
        print(io, "    ", vrp.prefix, "-", vrp.maxlength, "\n")
    end
end

function rawv4_to_roa(o::RPKIObject{ROA}, roa_ipaddress::Node) :: RPKIObject{ROA}
    tagisa(roa_ipaddress, ASN.SEQUENCE)
    tagisa(roa_ipaddress[1], ASN.BITSTRING)

    prefix = bitstring_to_v4prefix(roa_ipaddress[1].tag.value)
    maxlength = prefix.netmask #FIXME @code_warntype ?

    # optional maxLength:
    if length(roa_ipaddress.children) == 2
        tagisa(roa_ipaddress[2], ASN.INTEGER)
        @assert roa_ipaddress[2].tag.len == 1
        #if ASN.value(roa_ipaddress[2].tag) == maxlength
        if roa_ipaddress[2].tag.value[1] == maxlength
            info!(roa_ipaddress[2], "redundant maxLength")
        else
            maxlength = roa_ipaddress[2].tag.value[1]
        end
    end
    push!(o.object.vrps, VRP(prefix, maxlength))
    o
end
function rawv6_to_roa(o::RPKIObject{ROA}, roa_ipaddress::Node) :: RPKIObject{ROA}
    tagisa(roa_ipaddress, ASN.SEQUENCE)
    tagisa(roa_ipaddress[1], ASN.BITSTRING)

    prefix = bitstring_to_v6prefix(roa_ipaddress[1].tag.value)
    maxlength = prefix.netmask

    # optional maxLength:
    if length(roa_ipaddress.children) == 2
        tagisa(roa_ipaddress[2], ASN.INTEGER)
        explicit_len = if roa_ipaddress[2].tag.len == 1
            #@debug roa_ipaddress[2].tag.value
            roa_ipaddress[2].tag.value[1]
        elseif roa_ipaddress[2].tag.len == 2
            reinterpret(Int16, [roa_ipaddress[2].tag.value[2], roa_ipaddress[2].tag.value[1]])[1]
        else
            value(roa_ipaddress[2].tag)
        end
        if explicit_len == maxlength
            info!(roa_ipaddress[2], "redundant maxLength")
        else
            maxlength = explicit_len
        end
    end

    push!(o.object.vrps, VRP(prefix, maxlength))
    o
end

function check_ipaddrblocks(o::RPKIObject{ROA}, ipaddrblocks::Node) :: RPKIObject{ROA}
    tagisa(ipaddrblocks, ASN.SEQUENCE)
    if length(ipaddrblocks.children) == 0
        err!(ipaddrblocks, "there should be at least one ROAIPAddressFamily here")
    end
    for roa_afi in ipaddrblocks.children
        tagisa(roa_afi, ASN.SEQUENCE)
        # addressFamily
        tagisa(roa_afi[1], ASN.OCTETSTRING)
        afi = reinterpret(UInt16, reverse(roa_afi[1].tag.value))[1]
        if ! (afi in [1,2])
            @error "invalid AFI in ROA"
            err!(roa_afi[1], "addressFamily MUST be either 0002 for IPv6 or 0001 for IPv4")
        end
        addresses = roa_afi[2]
        tagisa(addresses, ASN.SEQUENCE)
        if length(addresses.children) == 0
            err!(addresses, "there should be at least one ROAIPAddress here")
        end
        if afi == 1 # IPv4
            for roa_ipaddress in addresses.children
                rawv4_to_roa(o, roa_ipaddress)
            end
        else
            for roa_ipaddress in addresses.children
                rawv6_to_roa(o, roa_ipaddress)
            end
        end
    end
    o
end

function check_route_origin_attestation(o::RPKIObject{ROA}, roa::Node) :: RPKIObject{ROA}
    @assert roa.tag isa ASN.Tag{ASN.SEQUENCE}
    tagisa(roa, ASN.SEQUENCE)

    # TODO again D-R-Y: see check_manifest
    # Version
    checkchildren(roa, 2:3)
    # the 'version' is optional, defaults to 0
    offset = 0
    if length(roa.children) == 3
        offset = 1
        # version:
        tagis_contextspecific(roa[1], 0x00)
        # EXPLICIT tagging, so the version must be in a child
        checkchildren(roa[1], 1)
        tagisa(roa[1, 1], ASN.INTEGER)
        if value(roa[1, 1].tag) == 0
            info!(roa[1, 1], "version explicitly set to 0 while that is the default")
        else
            err!(roa[1, 1], "version MUST be 0, found $(value(roa[1,1].tag))")
        end
    else
        @assert length(roa.children) == 2
        #info!(roa, "no version, assuming default 0")
    end
    # --- till here ---

    #@debug "early return"
    #return o
    
    # ASID
    asid = roa[offset + 1]
    tagisa(asid, ASN.INTEGER)
    o.object.asid = value(asid.tag)

    # ipAddrBlocks
    ipaddrblocks = roa[offset + 2]
    o = check_ipaddrblocks(o, ipaddrblocks)
    
    o
end

function check_SignerInfos(o::RPKIObject{ROA}, tpi::TmpParseInfo, si::Node) :: RPKIObject{ROA}
    tagisa(si, ASN.SET) 
	# checkchildren?

    tagisa(si[1], ASN.SEQUENCE) 
    # CMSVersion, MUST be 3
    tagvalue(si[1, 1], ASN.INTEGER, 0x03)

    # TODO:
    #   For RPKI signed objects, the sid MUST be the SubjectKeyIdentifier
    #   that appears in the EE certificate carried in the CMS certificates
    #   field. This is also true for MFTs

	# SignerIdentifier == SubjectKeyIdentifier [0]
	tagis_contextspecific(si[1, 2], 0x00)
    if si[1, 2].tag.value != tpi.subjectKeyIdentifier
        err!(si[1, 2], "SignerIdentifier does not match SubjectKeyIdentifier")
    end

	# DigestAlgorithmIdentifier
    tagisa(si[1,3], ASN.SEQUENCE)
    # MUST be SHA-256
    tag_OID(si[1,3,1], @oid "2.16.840.1.101.3.4.2.1")
    ##TODO D-R-Y with MFT.jl
    if length(si[1,3].children) == 2 
        tagisa(si[1,3,2], ASN.NULL)
        info!(si[1,3,2], "this NULL SHOULD be absent (RFC4055)")
    end

	# signedAttrs [0]
	# The signedAttrs element MUST be present and MUST include the content-
    # type and message-digest attributes [RFC5652].
    sa = si[1,4]

    # contentType MUST match the eContentType in the EncapsulatedContentInfo
    # in this case, it must be a "routeOriginAttest"
    contentType = containAttributeTypeAndValue(sa, @oid("1.2.840.113549.1.9.3"), ASN.SET)
    tag_OID(contentType[1], @oid "1.2.840.113549.1.9.16.1.24")

    messageDigest = containAttributeTypeAndValue(sa, @oid("1.2.840.113549.1.9.4"), ASN.SET)
    messageDigestValue = bytes2hex(messageDigest[1].tag.value)

    if messageDigestValue != o.object.local_eContent_hash
        @error "message-digest invalid" o.filename messageDigestValue o.object.local_eContent_hash
        err!(messageDigest[1], "invalid digest, expecting $(o.object.local_eContent_hash)")
    end

    # TODO implement get_attributes similarly to get_extensions (see
    # validation_common)
    # Signing-Time MAY be present
    #sa_attributes = get_attributes(sa)
    #if @oid("1.2.840.113549.1.9.5") in keys(sa_attributes)
    #    @debug "found signing_time"
    #end

	# signatureAlgorithm
	tagisa(si[1,5], ASN.SEQUENCE)
    # MUST be 1.2.840.113549.1.1.11
    checkchildren(si[1,5], 2)
    tag_OID(si[1,5,1], @oid "1.2.840.113549.1.1.11")
    # and here we MUST have a NULL for it's parameters
    tagisa(si[1,5,2], ASN.NULL)

    # skip check here, and do it in check_signature
	# signature
	# tagisa(si[1,6], ASN.OCTETSTRING)
    
    o
end

function check_certificates(o::RPKIObject{ROA}, tpi::TmpParseInfo, certs::Node) :: RPKIObject{ROA}
    #TODO: this is likely similar (identical?) to what is going on in CER.jl
    #D-R-Y and put this in X509.jl or something
    tagis_contextspecific(certs, 0x00)

    # "contains one EE certificate"
    checkchildren(certs, 1)
   
    
    tbscert = certs[1,1]
    

    # extract RSA modulus and exponent
    
    tagisa(tbscert[7, 2], ASN.BITSTRING)
    # here we go for a second pass:
    # skip the first byte as it will be 0,
    #   indicating the number if unused bits in the last byte
    
    encaps_buf = DER.Buf(tbscert[7, 2].tag.value[2:end])
    DER.parse_append!(encaps_buf, tbscert[7, 2])
   
    encaps_modulus  = tbscert[7, 2, 1, 1]
    encaps_exponent = tbscert[7, 2, 1, 2]
    # RFC6485:the exponent MUST be 65537
    tagvalue(encaps_exponent, ASN.INTEGER, 65_537)

    # TODO: (why) is this always 257?
    @assert encaps_modulus.tag.len == 257
    o.object.rsa_modulus   = to_bigint(encaps_modulus.tag.value[2:end])
    o.object.rsa_exp       = ASN.value(encaps_exponent.tag)


    # Check the extensions [3]
    #
    mandatory_extensions = Vector{Vector{UInt8}}()

    # Subject Key Identifier, MUST appear
    #check_extension(extensions, "2.5.29.14") # non-critical, 160bit SHA-1
    push!(mandatory_extensions, @oid "2.5.29.14")

    # Check all mandatory extensions are present
    # After that, we will validate their actual contents
    extensions = tbscert[8]
    check_extensions(extensions, mandatory_extensions)
    all_extensions = get_extensions(extensions)


    # Check contents of mandatory / available extensions

    encaps_subjectKeyIdentifier = all_extensions[@oid "2.5.29.14"]
    DER.parse_append!(DER.Buf(encaps_subjectKeyIdentifier.tag.value), encaps_subjectKeyIdentifier)
    #subjectKeyIdentifier = bytes2hex(encaps_subjectKeyIdentifier[1].tag.value)
    tpi.subjectKeyIdentifier = encaps_subjectKeyIdentifier[1].tag.value

    # must match the sid field in the SignerInfo

    o
end

function check_signed_data(o::RPKIObject{ROA}, tpi::TmpParseInfo, sd::Node) :: RPKIObject{ROA}
    # TODO refactor: first part overlaps with check_signed_data for MFT

    # Signed-Data as defined in RFC 5652 (CMS) can contain up to 6 children
    # but for RPKI Manifests/ROAs, we MUST have the CertificateSet and MUST NOT
    # have the RevocationInfoChoices
    checkchildren(sd, 5)

    # CMSVersion
    tagvalue(sd[1], ASN.INTEGER, 0x03)

    # DigestAlgorithmIdentifiers
    tagisa(sd[2], ASN.SET) 
    tagisa(sd[2,1], ASN.SEQUENCE)
    tag_OID(sd[2,1,1], @oid "2.16.840.1.101.3.4.2.1")
    #tagisa(sd[2,1,2], ASN.NULL)
    #TODO D-R-Y with MFT.jl
    if length(sd[2,1].children) == 2 
        tagisa(sd[2,1,2], ASN.NULL)
        info!(sd[2,1,2], "this NULL SHOULD be absent (RFC4055)")
    end

    # ----- here things are different for .roa compared to .mft

    # EncapsulatedContentInfo
    tagisa(sd[3], ASN.SEQUENCE)
    eContentType = sd[3,1]
    eContent = sd[3,2]

    tag_OID(eContentType, @oid "1.2.840.113549.1.9.16.1.24")
    tagis_contextspecific(eContent, 0x00)
    tagisa(eContent[1], ASN.OCTETSTRING)

    # to the second pass over the OCTETSTRING in the eContent
    # Here, in case of BER(?), an indefinite tag might already be parsed so we
    # do NOT need the second pass

    # TODO partly copied from MFT.jl, D-R-Y
    roa = if ! eContent[1].tag.len_indef
        DER.parse_append!(DER.Buf(eContent[1].tag.value), eContent[1])
        o.object.local_eContent_hash =  bytes2hex(sha256(eContent[1].tag.value))
        eContent[1, 1]
    else
        # already parsed, but can we spot the chunked OCTETSTRING case?
        if length(eContent[1].children) > 1
            #TODO check on the 1000 byte limit of CER
            warn!(eContent[1], "looks like CER instead of DER")
            concatted = collect(Iterators.flatten([n.tag.value for n in eContent[1].children]))
            buf = DER.Buf(concatted)
            DER.parse_replace_children!(buf, eContent[1])
            o.object.local_eContent_hash = bytes2hex(sha256(concatted))
            eContent[1, 1]
        else
            DER.parse_append!(DER.Buf(eContent[1, 1].tag.value), eContent[1, 1])
            o.object.local_eContent_hash = bytes2hex(sha256(eContent[1,1].tag.value))
            eContent[1, 1, 1]
        end
    end

    o = check_route_origin_attestation(o, roa)
    o = check_certificates(o, tpi, sd[4])
    o = check_SignerInfos(o, tpi, sd[5])
    o
end


# attempt at collecting the remarks from o.tree so we can form a quicklist at
# the RPKIObject level
# because we have many helpers (validation_common.jl) that are unaware of the
# RPKIObject when they are called, we need to collect the remarks from the ASN1
# tree after fully check()ing the object/tree
# TODO move this function to Common.jl or similar, so CER/MFT/CRL can use it as
# well
#function collect_remarks!(o::RPKIObject{ROA}, node::Node)
#    if !isnothing(node.remarks)
#        Base.append!(o.remarks_tree, node.remarks)
#    end
#    if !isnothing(node.children)
#        for c in node.children
#            collect_remarks!(o, c)
#        end
#    end
#end
# MOVED TO RPKI.jl

function check(o::RPKIObject{ROA}, tpi::TmpParseInfo=TmpParseInfo()) :: RPKIObject{ROA}
    o.remarks_tree = []
    cmsobject = o.tree
    #CMS, RFC5652
    tagisa(o.tree, ASN.SEQUENCE)
    tag_OID(o.tree[1], @oid "1.2.840.113549.1.7.2") # contentType
    tagis_contextspecific(o.tree[2], 0x00) # content

    ## 6488:
    tagisa(o.tree[2, 1], ASN.SEQUENCE)
    o = check_signed_data(o, tpi, o.tree[2, 1])
    
    #collect_remarks!(o, o.tree)
    o
end

function check_cert_chain(o::RPKIObject{ROA}, parent::RPKINode, lookup::Lookup) ::RPKIObject{ROA}
    tbscert = o.tree[2, 1, 4, 1, 1]
    issuer  = tbscert[4, 1, 1, 2]
    subject = tbscert[6, 1, 1, 2]

    if ASN.value(issuer.tag) != parent.parent.obj.object.subject
        @error "issuer/subject mismatch" o.filename
    end

    #TODO: subject must match signer_info SKI
    # so the signature of the embedded cert can be verified using the
    # parent.parent RSA modulus/exp (TODO: D-R-Y ..)

    sig = o.tree[2, 1, 4, 1, 3]
    signature = to_bigint(sig.tag.value[2:end])

    v = powermod(signature, parent.parent.obj.object.rsa_exp, parent.parent.obj.object.rsa_modulus)
    v.size = 4
    v_str = string(v, base=16, pad=64)

    tbs_raw = read(o.filename, tbscert.tag.offset_in_file + tbscert.tag.len + 4 - 1)[tbscert.tag.offset_in_file+0:end]
    my_hash = bytes2hex(sha256(tbs_raw))

    if v_str != my_hash
        @error "invalid hash for" o.filename parent.parent.obj.filename
    end
    
    o
end

function check_signature(o::RPKIObject{ROA}, parent::RPKINode, lookup::Lookup) :: RPKIObject{ROA}
    sig = o.tree[2, 1, 5, 1, 6]
    signature = to_bigint(sig.tag.value)


    # Decrypt signature using the EE certificate in the ROA 
    v = powermod(signature, o.object.rsa_exp, o.object.rsa_modulus)
    v.size = 4
    v_str = string(v, base=16, pad=64)

    # Locally hash the signedAttrs so we can compare it to v_str
    signedAttrs = o.tree[2,1,5,1,4]
    sa_raw = read(o.filename, signedAttrs.tag.offset_in_file - 1 + signedAttrs.tag.len + 2 )[signedAttrs.tag.offset_in_file:end]

    # the hash is calculated based on the DER EXPLICIT SET OF tag, not the
    # IMPLICIT [0], so we overwrite the first byte:
    sa_raw[1] = 0x11 | 0b00100000

    local_hash = bytes2hex(sha256(sa_raw))

    if v_str != local_hash
        push!(lookup.invalid_signatures, o)
        @error "signature invalid" o.filename
    else
        sig.validated = true
    end
    o
end
