module X509
using .....JDR.Common
using ....JDR.RPKICommon
using ....ASN
using ....DER
using IPNets

import ...PKIX.@check

const MANDATORY_EXTENSIONS = Vector{Pair{Vector{UInt8}, String}}([
                                                    @oid("2.5.29.14") => "basicConstraints",
                                                    @oid("2.5.29.15") =>  "keyUsage",
                                                    @oid("1.3.6.1.5.5.7.1.11") =>  "subjectInfoAccess",
                                                    @oid("2.5.29.32") =>  "certificatePolicies",
                                                   ])


@check "subjectInfoAccess" begin
    tagisa(node, ASN.OCTETSTRING)
    # Need a second pass to decode the OCTETSTRING
    DER.parse_append!(DER.Buf(node.tag.value), node)
    # MUST be present:
    # 1.3.6.1.5.5.7.48.5 caRepository
    # 1.3.6.1.5.5.7.48.10 rpkiManifest
    # could be present:
    # 1.3.6.1.5.5.7.48.13 RRDP notification URL
    tagisa(node[1], ASN.SEQUENCE)
    carepo_present = false
    manifest_present = false
    for access_description in node[1].children
        tagisa(access_description, ASN.SEQUENCE)
        checkchildren(access_description, 2)
        tagisa(access_description[1], ASN.OID)
        # [6] is a uniformResourceIdentifier, RFC5280
        tagis_contextspecific(access_description[2], 0x06)

        #now check for the MUST-be presents:
        if access_description[1].tag.value == @oid "1.3.6.1.5.5.7.48.5"
            access_description[1].nicename = "caRepository"
            carepo_present = true
            if o.object isa CER
                o.object.pubpoint = String(copy(access_description[2].tag.value))
            end
        end
        if access_description[1].tag.value == @oid "1.3.6.1.5.5.7.48.10"
            access_description[1].nicename = "rpkiManifest"
            manifest_present = true
            if o.object isa CER
                o.object.manifest = String(copy(access_description[2].tag.value))
            end
        end
        if access_description[1].tag.value == @oid "1.3.6.1.5.5.7.48.13"
            access_description[1].nicename = "rpkiNotify"
            if o.object isa CER
                o.object.rrdp_notify = String(copy(access_description[2].tag.value))
            end
        end
    end
    if o.object isa CER
        if !carepo_present
            err!(node, "missing essential caRepository")
        end
        if !manifest_present
            err!(node, "missing essential rpkiManifest")
        end
    end
end

@check "ipAddrBlocks" begin
    DER.parse_append!(DER.Buf(node.tag.value), node)
    node.validated = true
    tagisa(node[1], ASN.SEQUENCE)
    for ipaddrblock in node[1].children 
        tagisa(ipaddrblock, ASN.SEQUENCE)
        tagisa(ipaddrblock[1], ASN.OCTETSTRING)
        afi = reinterpret(UInt16, reverse(ipaddrblock[1].tag.value))[1]
        @assert afi in [1,2] # 1 == IPv4, 2 == IPv6
        # now, or a NULL -> inherit
        # or a SEQUENCE OF IPAddressOrRange
        if typeof(ipaddrblock[2].tag) == Tag{ASN.SEQUENCE}
            ipaddrblock[2].validated = true
            # now loop over children of this SEQUENCE OF IPAddressOrRange 
            for ipaddress_or_range in ipaddrblock[2].children

                #if typeof(ipaddrblock[2, 1].tag) == Tag{ASN.SEQUENCE}
                if ipaddress_or_range.tag isa Tag{ASN.SEQUENCE}

                    ipaddress_or_range.validated = true
                    # if child is another SEQUENCE, we have an IPAddressRange
                    #throw("check me")

                    # we expect two BITSTRINGs in this SEQUENCE
                    tagisa(ipaddress_or_range[1], ASN.BITSTRING)
                    tagisa(ipaddress_or_range[2], ASN.BITSTRING)
                    if afi == 1
                        (minaddr, maxaddr) = bitstrings_to_v4range(
                                                ipaddress_or_range[1].tag.value,
                                                ipaddress_or_range[2].tag.value
                                              )
                        push!(o.object.prefixes, IPRange{IPv4Net}(minaddr, maxaddr))
                    else
                        (minaddr, maxaddr) = bitstrings_to_v6range(
                                                ipaddress_or_range[1].tag.value,
                                                ipaddress_or_range[2].tag.value
                                              )
                        push!(o.object.prefixes, IPRange{IPv6Net}(minaddr, maxaddr))
                    end
                #elseif typeof(ipaddrblock[2, 1].tag) == Tag{ASN.BITSTRING}
                elseif ipaddress_or_range.tag isa Tag{ASN.BITSTRING}
                    ipaddress_or_range.validated = true
                    # else if it is a BITSTRING, we have an IPAddress (prefix)
                    #@debug "IPAddress (prefix)"
                    bitstring = ipaddress_or_range.tag.value
                    if afi == 1
                        push!(o.object.prefixes, bitstring_to_v4prefix(bitstring))
                    else
                        push!(o.object.prefixes, bitstring_to_v6prefix(bitstring))
                    end
                else
                    @error "unexpected tag number $(ipaddress_or_range.tag.number)"
                end
            end # for-loop over SEQUENCE OF IPAddressOrRange
        elseif ipaddrblock[2].tag isa Tag{ASN.NULL}
            #throw("implement inherit for ipAdressBlocks")
            #@error "implement inherit for ipAdressBlocks"
            if o.object isa CER
                o.object.inherit_prefixes = true
            end
        else
            warn!(ipaddrblock[2], "expected either SEQUENCE OF or NULL here")
        end
    end
    #IP
end

@check "autonomousSysIds" begin
    DER.parse_append!(DER.Buf(node.tag.value), node)
    node.validated = true
    tagisa(node[1], ASN.SEQUENCE)
    for asidentifierchoice in node[1].children 
        # expect either a [0] or [1]
        tagisa(asidentifierchoice, ASN.CONTEXT_SPECIFIC)
        if asidentifierchoice.tag.number == 0
            #DER.parse_append!(DER.Buf(asidentifierchoice.tag.value), asidentifierchoice)
            # or NULL (inherit) or SEQUENCE OF ASIdOrRange
            if asidentifierchoice[1].tag isa Tag{ASN.NULL}
                if o.object isa CER
                    o.object.inherit_ASNs = true
                end
                #throw("implement inherit for ASIdentifierChoice")
            elseif asidentifierchoice[1].tag isa Tag{ASN.SEQUENCE}
                # now it can be or a single INTEGER, or again a SEQUENCE
                asidentifierchoice[1].validated = true
                for asid_or_range in asidentifierchoice[1].children
                    if asid_or_range.tag isa Tag{ASN.INTEGER}
                        asid = UInt32(ASN.value(asid_or_range.tag))
                        push!(o.object.ASNs, AutSysNum(asid))
                        asid_or_range.validated = true
                    elseif asid_or_range.tag isa Tag{ASN.SEQUENCE}
                        asmin = UInt32(ASN.value(asid_or_range[1].tag))
                        asmax = UInt32(ASN.value(asid_or_range[2].tag))
                        push!(o.object.ASNs, AutSysNumRange(asmin, asmax))
                        asid_or_range.validated = true
                        asid_or_range[1].validated = true
                        asid_or_range[2].validated = true
                    else
                        warn!(asid_or_range[1], "unexpected tag number $(asid_or_range[1].tag.number)")
                    end
                end #for-loop asid_or_range
            else
                warn!(asidentifierchoice[1], "expected either a SEQUENCE OF or a NULL here")
            end

        elseif asidentifierchoice.tag.number == 1
            throw("implement rdi for ASIdentifierChoice")
        else
            warn!(asidentifierchoice, "Unknown Context-Specific tag number, expecting 0 or 1")
        end
    end
end

function check_ASN1_extension(oid::Vector{UInt8}, o::RPKIObject{T}, node::Node, tpi::TmpParseInfo) where T
    if oid == @oid("1.3.6.1.5.5.7.1.11")
        check_ASN1_subjectInfoAccess(o, node, tpi)
    elseif oid == @oid("1.3.6.1.5.5.7.1.7")
        check_ASN1_ipAddrBlocks(o, node, tpi)
    elseif oid == @oid("1.3.6.1.5.5.7.1.8")
        check_ASN1_autonomousSysIds(o, node, tpi)
    else
        @warn "Unknown oid $(oid) passed to X509::check_extension" maxlog=10
        warn!(node, "Unknown extension")
    end

end

@check "version"  begin
    # Version == 0x02? (meaning version 3)
    tagis_contextspecific(node, 0x0)
    tagvalue(node[1], ASN.INTEGER, 0x02)
end

@check "serialNumber" begin
    tagisa(node, ASN.INTEGER)
    # do we need the serial? 
    if o.object isa CER
        o.object.serial = ASN.value(node.tag, force_reinterpret=true)
    end
end

@check "signature" begin
    tagisa(node, ASN.SEQUENCE)

    tag_OID(node[1], @oid "1.2.840.113549.1.1.11")
    if checkchildren(node, 2)
        tagisa(node[2], ASN.NULL) # TODO be more explicit in the remark
    end
end

@check "issuer" begin
    # Issuer = Name = RDNSequence = SEQUENCE OF RelativeDistinguishedName
    tagisa(node, ASN.SEQUENCE)
    issuer_set = node[1]
    tagisa(issuer_set, ASN.SET)
        # it's a SET of AttributeTypeAndValue 
        # which is a SEQUENCE of type (OID) + value (ANY)
        # from RFC6487:
		# An issuer name MUST contain one instance of the CommonName attribute
		#   and MAY contain one instance of the serialNumber attribute.  If both
		#   attributes are present, it is RECOMMENDED that they appear as a set.
		#   The CommonName attribute MUST be encoded using the ASN.1 type
		#   PrintableString [X.680].
		# FIXME question: what would such a RECOMMENDED set look like?
		# is it a SET of SEQUENCEs(==AttributeTypeValue) within the SET(==RelDisName) ?

    checkchildren(issuer_set, 1:2)
    # If the issuer contains the serialNumber as well,
    # the set should contain 1 child, the RECOMMENDED set
    # TODO check this interpretation
    issuer = containAttributeTypeAndValue(issuer_set, @oid("2.5.4.3"), ASN.PRINTABLESTRING)
    if o.object isa CER
        o.object.issuer = ASN.value(issuer.tag)
        push!(tpi.issuer, ASN.value(issuer.tag))
    end

	if length(issuer_set.children) > 1
	    # if size == 2, the second thing must be a CertificateSerialNumber
        @error "TODO: serialNumber in Issuer"
    end
end

@check "validity" begin
    # SEQUENCE of 2x Time, which is a CHOICE of utcTime/generalTime
    tagisa(node, ASN.SEQUENCE)
    tagisa(node[1], [ASN.UTCTIME, ASN.GENTIME])
    tagisa(node[2], [ASN.UTCTIME, ASN.GENTIME])
end

@check "subject" begin
    tagisa(node, ASN.SEQUENCE)
    # RFC6487:
    #  Each distinct subordinate CA and
    #  EE certified by the issuer MUST be identified using a subject name
    #  that is unique per issuer.
    #  TODO can we check on this? not here, but in a later stage?
    subject = containAttributeTypeAndValue(node[1], @oid("2.5.4.3"), ASN.PRINTABLESTRING)
    #@debug "CER, subject:" ASN.value(subject.tag)

    if o.object isa CER
        o.object.subject = ASN.value(subject.tag)
        o.object.selfsigned = o.object.issuer == o.object.subject
    end
end

@check "algorithm" begin
    tagisa(node, ASN.SEQUENCE)
    # FIXME: RFC6485 is not quite clear on which OID we should expect here..
    tag_OID(node[1], @oid "1.2.840.113549.1.1.1")
    tagisa(node[2], ASN.NULL)
end

@check "subjectPublicKey" begin
    tagisa(node, ASN.BITSTRING)

    # Now we go for a second pass:
    # skip the first byte as it will be 0, 
    # indicating the number if unused bits in the last byte
    
    encaps_buf = DER.Buf(node.tag.value[2:end])
    DER.parse_append!(encaps_buf, node)

    tagisa(node[1], ASN.SEQUENCE)
    tagisa(node[1,1], ASN.INTEGER)
   
    encaps_modulus  = node[1, 1]
    encaps_exponent = node[1, 2]
    # RFC6485:the exponent MUST be 65537
    tagvalue(encaps_exponent, ASN.INTEGER, 65_537)

    # 256 bytes + the first byte indicating unused bits == 257
    @assert encaps_modulus.tag.len == 257
    if o.object isa CER
        # OLD, maybe remove:
        o.object.rsa_modulus   = to_bigint(encaps_modulus.tag.value[2:end])
        o.object.rsa_exp       = ASN.value(encaps_exponent.tag)
        # for use in RPKI::process_cer/mft/roa()

        #tpi.ca_rsaModulus   = to_bigint(encaps_modulus.tag.value[2:end])
        #tpi.ca_rsaExponent  = encaps_exponent

        # attempt to use a stack
        #@debug ("push, now $(length(tpi.ca_rsaModulus))")
        push!(tpi.ca_rsaModulus, to_bigint(encaps_modulus.tag.value[2:end]) )
        push!(tpi.ca_rsaExponent, ASN.value(encaps_exponent.tag))
    end
    if o.object isa ROA || o.object isa MFT
        tpi.ee_rsaExponent = encaps_exponent
        tpi.ee_rsaModulus = encaps_modulus
    end
end

@check "subjectPublicKeyInfo" begin
    # AlgorithmIdentifier + BITSTRING
    tagisa(node, ASN.SEQUENCE)
    (@__MODULE__).check_ASN1_algorithm(o, node[1], tpi)
    (@__MODULE__).check_ASN1_subjectPublicKey(o, node[2], tpi)
end

const MANDATORY_EXTENSIONS_SS = Vector{Vector{UInt8}}([
                                                   ])

const MANDATORY_EXTENSIONS_CA = Vector{Vector{UInt8}}([
                                                   ])

const MANDATORY_EXTENSIONS_EE = Vector{Vector{UInt8}}([
                                                   ])

@check "extensions" begin
    tagis_contextspecific(node, 0x3)

    mandatory_extensions = Vector{Vector{UInt8}}()

    # in order as listed in RFC6487:
    # 2.5.29.19 basicConstraints
    # MUST appear if subject == CA, otherwise MUST NOT be here
    # RFC 6487 4.8.1 unclear:
    #   'The issuer determines whether the "cA" boolean is set.'
    # if this extension is here, the value is always true?
    # so the boolean is actually sort of redundant?
    # because when the subject is not a CA, this extension MUST NOT be here
    # TODO: store whether or not this CER is a CA CER?
    

    # Subject Key Identifier, MUST appear
    push!(mandatory_extensions, @oid "2.5.29.14")

    # Authority Key Identifier
	# RFC 6487:
	#  This extension MUST appear in all resource certificates, with the
	#  exception of a CA who issues a "self-signed" certificate.  In a self-
	#  signed certificate, a CA MAY include this extension, and set it equal
	#  to the Subject Key Identifier.
    #  2.5.29.35 authorityKeyIdentifier
    #TODO:
    #check self_signed
    #if/else on that

	# Key Usage, MUST appear
	# RFC 6487:
	#  In certificates issued to certification authorities only, the
	#  keyCertSign and CRLSign bits are set to TRUE, and these MUST be the
	#  only bits set to TRUE.
	#
	#  In EE certificates, the digitalSignature bit MUST be set to TRUE and
	#  MUST be the only bit set to TRUE.
    #2.5.29.15 keyUsage
    push!(mandatory_extensions, @oid "2.5.29.15")

	# Extended Key Usage
	# may only appear in specific certs
	# TODO should we check for this NOT being here then?

    # CRL Distribution Points
    # MUST be present, except in self-signed
    # TODO so are the RIR TA .cers all self-signed?
    # 2.5.29.31 cRLDistributionPoints

    # Authority Information Access
    # 1.3.6.1.5.5.7.1.1 authorityInfoAccess
    # non critical
    # MUST be present in non-selfsigned certs
    # must have an 1.3.6.1.5.5.7.48.2 caIssuers containing an rsync URI

    # Subject Information Access, MUST be present
    # 1.3.6.1.5.5.7.1.11 subjectInfoAccess
    ## SIA for CA Certificates MUST be present, MUST be non-critical
    push!(mandatory_extensions, @oid "1.3.6.1.5.5.7.1.11")
    ### MUST have an caRepository (OID 1.3.6.1.5.5.7.48.5)
    ### MUST have a rpkiManifest (OID 1.3.6.1.5.5.7.48.10) pointing to an rsync uri
    # TODO rrdp stuff is in another RFC
    
    ## SIA for EE Certificates MUST be present, MUST be non-critical
    # MUST contain 1.3.6.1.5.5.7.48.11 signedObject pointing to rsync uri
    # for the signedObject

    # Certificate Policies MUST present+critical
    # MUST contain one policy, RFC6484
    # 2.5.29.32 certificatePolicies
    push!(mandatory_extensions, @oid "2.5.29.32")
    # MUST contain exactly one, 1.3.6.1.5.5.7.14.2 resourceCertificatePolicy

    # IP + AS resources
    # RFC6487: one or both MUST be present+critical
    # see RFC 3779 for these specific X.509 Extensions
    #
    # ipAddrBlocks
    # SEQUENCE OF IPAddressFamily
    # IPAddressFamily type is a SEQUENCE containing an addressFamily
    #    and ipAddressChoice element.
    #
    # TODO: if v4+v6 in one extension, v4 must come first
    #


    # get all extensions, check presence of mandatory extensions
    # make sure we do not mark the extension as 'checked' in the ASN tree here
    # yet, we mark it in the check_ASN1_ functions/macros

    #check_extensions(node, mandatory_extensions)
    check_extensions(node, (@__MODULE__).MANDATORY_EXTENSIONS)
    all_extensions = get_extensions(node)

    # Resource certificate MUST have either or both of the IP and ASN Resources
    # extensions:
    # TODO check this

    # now check all extensions based on their type:
    # TODO iterate over all_extensions, call check_ASN1_$nicename
    # hardcode a macro/dict with OID<-->nicename?
    # @warn on OIDs for which we have no function


    # SIA checks # TODO rewrite / split up check_subject_information_access
    #RPKI.check_subject_information_access(o, all_extensions[@oid "1.3.6.1.5.5.7.1.11"])
    for (oid,node) in all_extensions
        (@__MODULE__).check_ASN1_extension(oid, o, node, tpi)
    end

    # IP and/or ASN checks:
    # TODO: make sure we check either or both of IP and ASN extensions are there
    

    # or:
    # get all extensions (so return the OIDs)
    # and create a check_extension(OID{TypeBasedOnOIDString})
end

@check "tbsCertificate" begin
    (@__MODULE__).check_ASN1_version(o, node[1], tpi)
    (@__MODULE__).check_ASN1_serialNumber(o, node[2], tpi)
    (@__MODULE__).check_ASN1_signature(o, node[3], tpi)
    (@__MODULE__).check_ASN1_issuer(o, node[4], tpi)
    (@__MODULE__).check_ASN1_validity(o, node[5], tpi)
    (@__MODULE__).check_ASN1_subject(o, node[6], tpi)
    (@__MODULE__).check_ASN1_subjectPublicKeyInfo(o, node[7], tpi)
    (@__MODULE__).check_ASN1_extensions(o, node[8], tpi)

    if o.object isa ROA 
        tpi.eeCert = node
    elseif o.object isa MFT
        tpi.eeCert = node
    elseif o.object isa CER
        tpi.caCert = node
    else
        throw(ErrorException("what object?"))
    end
end


end # end module
