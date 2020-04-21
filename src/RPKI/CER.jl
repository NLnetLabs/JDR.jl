mutable struct CER 
    serial::Integer
    pubpoint::String
    manifest::String
    rrdp_notify::String
    inherit_prefixes::Bool
    prefixes::Vector{Union{IPNet, Tuple{IPNet, IPNet}}}
    inherit_ASNs::Bool
    ASNs::Vector{Union{Tuple{UInt32, UInt32}, UInt32}}
end
CER() = CER(0, "", "", "", false, [], false, [])

function Base.show(io::IO, cer::CER)
    print(io, "  pubpoint: ", cer.pubpoint, '\n')
    print(io, "  manifest: ", cer.manifest, '\n')
    print(io, "  rrdp: ", cer.rrdp_notify, '\n')
    printstyled(io, "  ASNs: \n")
    for a in cer.ASNs
        print(io, "    ", a, '\n')
    end
    printstyled(io, "  prefixes: \n")
    for p in cer.prefixes
        print(io, "    ", p, '\n')
    end
end

function check_subject_information_access(o::RPKIObject{CER}, subtree::Node)
    tagisa(subtree, ASN.OCTETSTRING)
    # second pass on the encapsulated  OCTETSTRING
    DER.parse_append!(DER.Buf(subtree.tag.value), subtree)

    # MUST be present:
    # 1.3.6.1.5.5.7.48.5 caRepository
    # 1.3.6.1.5.5.7.48.10 rpkiManifest
    # could be present:
    # 1.3.6.1.5.5.7.48.13 RRDP notification URL
    
    tagisa(subtree[1], ASN.SEQUENCE)
    carepo_present = false
    manifest_present = false
    for access_description in subtree[1].children
        tagisa(access_description, ASN.SEQUENCE)
        checkchildren(access_description, 2)
        tagisa(access_description[1], ASN.OID)
        # [6] is a uniformResourceIdentifier, RFC5280
        tagis_contextspecific(access_description[2], 0x06)

        #now check for the MUST-be presents:
        if access_description[1].tag.value == @oid "1.3.6.1.5.5.7.48.5"
            carepo_present = true
            o.object.pubpoint = String(copy(access_description[2].tag.value))
        end
        if access_description[1].tag.value == @oid "1.3.6.1.5.5.7.48.10"
            manifest_present = true
            o.object.manifest = String(copy(access_description[2].tag.value))
        end
        if access_description[1].tag.value == @oid "1.3.6.1.5.5.7.48.13"
            o.object.rrdp_notify = String(copy(access_description[2].tag.value))
        end
    end
    if !carepo_present
        remark!(subtree, "missing essential caRepository")
    end
    if !manifest_present
        remark!(subtree, "missing essential rpkiManifest")
    end
end

function checkTbsCertificate(o::RPKIObject{CER}, tbscert::Node)
    # Version == 0x02? (meaning version 3)
    tagis_contextspecific(tbscert[1], 0x0)
    #DER.parse_value!(tbscert[1])
    tagvalue(tbscert[1, 1], ASN.INTEGER, 0x02)

    # Serial number
    tagisa(tbscert[2], ASN.INTEGER)
    o.object.serial = ASN.value(tbscert[2].tag, force_reinterpret=true)

    # Signature AlgorithmIdentifier
    # SEQ / OID / NULL
    tagisa(tbscert[3], ASN.SEQUENCE)

    tag_OID(tbscert[3, 1], @oid "1.2.840.113549.1.1.11")
    if checkchildren(tbscert[3], 2)
        tagisa(tbscert[3, 2], ASN.NULL) # TODO be more explicit in the remark
    end

    # Issuer = Name = RDNSequence = SEQUENCE OF RelativeDistinguishedName
    tagisa(tbscert[4], ASN.SEQUENCE)
    issuer_set = tbscert[4, 1]
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
    containAttributeTypeAndValue(issuer_set, @oid("2.5.4.3"), ASN.PRINTABLESTRING)
	if length(issuer_set.children) > 1
	    # if size == 2, the second thing must be a CertificateSerialNumber
        @error "TODO: serialNumber in Issuer"
    end
    
    # Validity
    # SEQUENCE of 2x Time, which is a CHOICE of utcTime/generalTime
    tagisa(tbscert[5], ASN.SEQUENCE)
    tagisa(tbscert[5, 1], [ASN.UTCTIME, ASN.GENTIME])
    tagisa(tbscert[5, 2], [ASN.UTCTIME, ASN.GENTIME])


    # Subject
    # RFC6487:
    #  Each distinct subordinate CA and
    #  EE certified by the issuer MUST be identified using a subject name
    #  that is unique per issuer.
    #  TODO can we check on this? not here, but in a later stage?
    containAttributeTypeAndValue(tbscert[6, 1], @oid("2.5.4.3"), ASN.PRINTABLESTRING)

    # SubjectPublicKeyInfo
    # AlgorithmIdentifier + BITSTRING
    tagisa(tbscert[7], ASN.SEQUENCE)
    tagisa(tbscert[7, 1], ASN.SEQUENCE)
    # FIXME: RFC6485 is not quite clear on which OID we should expect here..
    tag_OID(tbscert[7, 1, 1], @oid "1.2.840.113549.1.1.1")
    tagisa(tbscert[7, 1, 2], ASN.NULL)
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


    # issuerUniqueID [1]
    # TODO

    # subjectUniqueID [2]
    # TODO

    # extensions [3]
    # MUST be present
    extensions = tbscert[8]
    tagis_contextspecific(extensions, 0x3)
    #DER.parse_value!(extensions)

    mandatory_extensions = Vector{Vector{UInt8}}()

    # RFC 6487 4.8.1 unclear:
    #   'The issuer determines whether the "cA" boolean is set.'
    # if this extension is here, the value is always true?
    # so the boolean is actually sort of redundant?
    # because when the subject is not a CA, this extension MUST NOT be here
    
    # Subject Key Identifier, MUST appear
    #check_extension(extensions, "2.5.29.14") # non-critical, 160bit SHA-1
    push!(mandatory_extensions, @oid "2.5.29.14")

    # Authority Key Identifier
	# RFC 6487:
	#  This extension MUST appear in all resource certificates, with the
	#  exception of a CA who issues a "self-signed" certificate.  In a self-
	#  signed certificate, a CA MAY include this extension, and set it equal
	#  to the Subject Key Identifier.
	#  check_extension(extensions, 

	# Key Usage, MUST appear
	# RFC 6487:
	#  In certificates issued to certification authorities only, the
	#  keyCertSign and CRLSign bits are set to TRUE, and these MUST be the
	#  only bits set to TRUE.
	#
	#  In EE certificates, the digitalSignature bit MUST be set to TRUE and
	#  MUST be the only bit set to TRUE.
	#check_extension(extensions, "2.5.29.15") # critical, 1byte BITSTRING
    push!(mandatory_extensions, @oid "2.5.29.15")

	# Extended Key Usage
	# may only appear in specific certs
	# TODO should we check for this NOT being here then?

    # CRL Distribution Points
    # MUST be present, except in self-signed
    # TODO so are the RIR TA .cers all self-signed?

    # Authority Information Access
    # non critical

    # Subject Information Access, MUST be present
    ## SIA for CA Certificates MUST be present, MUST be non-critical
    push!(mandatory_extensions, @oid "1.3.6.1.5.5.7.1.11")
    ### MUST have an caRepository (OID 1.3.6.1.5.5.7.48.5)
    ### MUST have a rpkiManifest (OID 1.3.6.1.5.5.7.48.10) pointing to an rsync uri
    # TODO rrdp stuff is in another RFC
    
    ## SIA for EE Certificates MUST be present, MUST be non-critical
    #TODO set up test with EE cert 

    # Certificate Policies MUST present+critical
    # MUST contain one policy, RFC6484

    # IP + AS resources
    # one or both MUST be present+critical
    # RFC 3779
    #
    # ipAddrBlocks
    # SEQUENCE OF IPAddressFamily
    # IPAddressFamily type is a SEQUENCE containing an addressFamily
    #    and ipAddressChoice element.
    #
    # TODO: if v4+v6 in one extension, v4 must come first
    #


    check_extensions(extensions, mandatory_extensions)
    all_extensions = get_extensions(extensions)


    # SIA checks
    check_subject_information_access(o, all_extensions[@oid "1.3.6.1.5.5.7.1.11"])

    # IP and/or ASN checks:
    
    if @oid("1.3.6.1.5.5.7.1.7") in keys(all_extensions)
        #@debug "got IP extension"
        subtree = all_extensions[@oid "1.3.6.1.5.5.7.1.7"]
        DER.parse_append!(DER.Buf(subtree.tag.value), subtree)
        subtree.validated = true
        tagisa(subtree[1], ASN.SEQUENCE)
        for ipaddrblock in subtree[1].children 
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
                            push!(o.object.prefixes, (minaddr, maxaddr))
                        else
                            (minaddr, maxaddr) = bitstrings_to_v6range(
                                                    ipaddress_or_range[1].tag.value,
                                                    ipaddress_or_range[2].tag.value
                                                  )
                            push!(o.object.prefixes, (minaddr, maxaddr))
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
                o.object.inherit_prefixes = true
            else
                remark!(ipaddrblock[2], "expected either SEQUENCE OF or NULL here")
            end
        end
        #IP
    else
        @assert @oid("1.3.6.1.5.5.7.1.8") in keys(all_extensions)
        # TODO properly add remark if this is missing
    end
    if @oid("1.3.6.1.5.5.7.1.8") in keys(all_extensions)
        #@debug "got ASN extension"
        subtree = all_extensions[@oid "1.3.6.1.5.5.7.1.8"]
        DER.parse_append!(DER.Buf(subtree.tag.value), subtree)
        subtree.validated = true
        tagisa(subtree[1], ASN.SEQUENCE)
        for asidentifierchoice in subtree[1].children 
            # expect either a [0] or [1]
            tagisa(asidentifierchoice, ASN.CONTEXT_SPECIFIC)
            if asidentifierchoice.tag.number == 0
                #DER.parse_append!(DER.Buf(asidentifierchoice.tag.value), asidentifierchoice)
                # or NULL (inherit) or SEQUENCE OF ASIdOrRange
                if asidentifierchoice[1].tag isa Tag{ASN.NULL}
                    o.object.inherit_ASNs = true
                    #throw("implement inherit for ASIdentifierChoice")
                elseif asidentifierchoice[1].tag isa Tag{ASN.SEQUENCE}
                    # now it can be or a single INTEGER, or again a SEQUENCE
                    asidentifierchoice[1].validated = true
                    for asid_or_range in asidentifierchoice[1].children
                        if asid_or_range.tag isa Tag{ASN.INTEGER}
                            asid = UInt32(ASN.value(asid_or_range.tag))
                            push!(o.object.ASNs, asid)
                            asid_or_range.validated = true
                        elseif asid_or_range.tag isa Tag{ASN.SEQUENCE}
                            asmin = UInt32(ASN.value(asid_or_range[1].tag))
                            asmax = UInt32(ASN.value(asid_or_range[2].tag))
                            push!(o.object.ASNs, (asmin, asmax))
                            asid_or_range.validated = true
                            asid_or_range[1].validated = true
                            asid_or_range[2].validated = true
                        else
                            remark!(asid_or_range[1], "unexpected tag number $(asid_or_range[1].tag.number)")
                        end
                    end #for-loop asid_or_range
                else
                    remark!(asidentifierchoice[1], "expected either a SEQUENCE OF or a NULL here")
                end

            elseif asidentifierchoice.tag.number == 1
                throw("implement rdi for ASIdentifierChoice")
            else
                remark!(asidentifierchoice, "Unknown Context-Specific tag number, expecting 0 or 1")
            end
        end
        
    end

    # or:
    # get all extensions (so return the OIDs)
    # and create a check_extension(OID{TypeBasedOnOIDString})
end

function check(o::RPKIObject{CER}) :: RPKIObject{CER}
    # The certificate should consist of three parts: (RFC5280)
	# Certificate  ::=  SEQUENCE  {
	#      tbsCertificate       TBSCertificate,
	#      signatureAlgorithm   AlgorithmIdentifier,
	#      signature            BIT STRING  }
    
    #checkchildren(o.tree, 3) # alternative to the popfirst! below
    checkchildren(o.tree, 3)
    tbsCertificate = o.tree.children[1]
    checkTbsCertificate(o, tbsCertificate)

    
    o
end
