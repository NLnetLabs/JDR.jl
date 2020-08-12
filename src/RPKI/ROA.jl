struct VRP{AFI<:IPNet}
    prefix::AFI
    maxlength::Integer
end

mutable struct ROA
    asid::Integer
    vrps::Vector{VRP}
end
ROA() = ROA(0, [])


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
    asid = roa[offset + 1] # TODO attach to o
    tagisa(asid, ASN.INTEGER)
    o.object.asid = value(asid.tag)

    # ipAddrBlocks
    ipaddrblocks = roa[offset + 2]
    o = check_ipaddrblocks(o, ipaddrblocks)
    
    o
end

function check_signed_data(o::RPKIObject{ROA}, sd::Node) :: RPKIObject{ROA}
    # TODO refactor: first part overlaps with check_signed_data for MFT

    # Signed-Data as defined in RFC 5652 (CMS) can contain up to 6 children
    # but for RPKI Manifests, we MUST have the CertificateSet and MUST NOT have
    # the RevocationInfoChoices
    checkchildren(sd, 5)

    # CMSVersion
    tagvalue(sd[1], ASN.INTEGER, 0x03)

    # DigestAlgorithmIdentifiers
    tagisa(sd[2], ASN.SET) 
    tagisa(sd[2,1], ASN.SEQUENCE)
    #tagvalue(sd[2,1,1], ASN.OID, "2.16.840.1.101.3.4.2.1")
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

    #tagvalue(eContentType, ASN.OID, "1.2.840.113549.1.9.16.1.24")
    tag_OID(eContentType, @oid "1.2.840.113549.1.9.16.1.24")
    tagis_contextspecific(eContent, 0x00)
    tagisa(eContent[1], ASN.OCTETSTRING)

    # to the second pass over the OCTETSTRING in the eContent
    # Here, in case of BER(?), an indefinite tag might already be parsed so we
    # do NOT need the second pass
    
   # roa = if ! eContent[1].tag.len_indef
   #     DER.parse_append!(DER.Buf(eContent[1].tag.value), eContent[1])
   #     eContent[1, 1]
   # else
   #     DER.parse_append!(DER.Buf(eContent[1, 1].tag.value), eContent[1, 1])
   #     eContent[1, 1, 1]
   # end

   # from MFT.jl:
    roa = if ! eContent[1].tag.len_indef
        DER.parse_append!(DER.Buf(eContent[1].tag.value), eContent[1])
        eContent[1, 1]
    else
        # already parsed, but can we spot the chunked OCTETSTRING case?
        if length(eContent[1].children) > 1
            #TODO check on the 1000 byte limit of CER
            warn!(eContent[1], "looks like CER instead of DER")
            #@debug "found multiple children in eContent[1]"
            concatted = collect(Iterators.flatten([n.tag.value for n in eContent[1].children]))
            buf = DER.Buf(concatted)
            DER.parse_replace_children!(buf, eContent[1])
            eContent[1, 1]
        else
            DER.parse_append!(DER.Buf(eContent[1, 1].tag.value), eContent[1, 1])
            eContent[1, 1, 1]
        end
    end


    o = check_route_origin_attestation(o, roa)
    o
end

function check(o::RPKIObject{ROA}) :: RPKIObject{ROA}
    cmsobject = o.tree
    #CMS, RFC5652
    tagisa(o.tree, ASN.SEQUENCE)
    #tagvalue(o.tree[1], ASN.OID, "1.2.840.113549.1.7.2") # contentType
    tag_OID(o.tree[1], @oid "1.2.840.113549.1.7.2") # contentType
    tagis_contextspecific(o.tree[2], 0x00) # content

    ## 6488:
    tagisa(o.tree[2, 1], ASN.SEQUENCE)
    o = check_signed_data(o, o.tree[2, 1])
    
    o
end

