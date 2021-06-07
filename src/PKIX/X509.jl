module X509
using JDR.Common: @oid, AutSysNum, AutSysNumRange, oid_to_str, remark_ASN1Error!, remark_ASN1Issue!
using JDR.RPKICommon: RPKIFile, RPKIObject, TmpParseInfo, CER, MFT, ROA, add_resource!
using JDR.ASN1: ASN1, check_tag, check_contextspecific, childcount, istag, check_value
using JDR.ASN1: check_OID, check_attribute, check_extensions, get_extensions
using JDR.ASN1: bitstring_to_v6range, bitstrings_to_v6range
using JDR.ASN1: bitstring_to_v4range, bitstrings_to_v4range, to_bigint
using JDR.ASN1.DER: DER

include("../ASN1/macro_check.jl")

const MANDATORY_EXTENSIONS = Vector{Pair{Vector{UInt8}, String}}([
                                                    @oid("2.5.29.14") => "subjectKeyIdentifier",
                                                    @oid("2.5.29.15") =>  "keyUsage",
                                                    @oid("1.3.6.1.5.5.7.1.11") =>  "subjectInfoAccess",
                                                    @oid("2.5.29.32") =>  "certificatePolicies",
                                                   ])


@check "subjectInfoAccess" begin
    check_tag(node, ASN1.OCTETSTRING)
    # Need a second pass to decode the OCTETSTRING
    DER.parse_append!(DER.Buf(node.tag.value), node)
    # MUST be present:
    # 1.3.6.1.5.5.7.48.5 caRepository
    # 1.3.6.1.5.5.7.48.10 rpkiManifest
    # could be present:
    # 1.3.6.1.5.5.7.48.13 RRDP notification URL
    check_tag(node[1], ASN1.SEQUENCE)
    carepo_present = false
    manifest_present = false
    for access_description in node[1].children
        check_tag(access_description, ASN1.SEQUENCE)
        childcount(access_description, 2)
        check_tag(access_description[1], ASN1.OID)
        # [6] is a uniformResourceIdentifier, RFC5280
        check_contextspecific(access_description[2], 0x06)

        #now check for the MUST-be presents:
        if access_description[1].tag.value == @oid "1.3.6.1.5.5.7.48.5"
            tpi.nicenames && (access_description[1].nicename = "caRepository")
            carepo_present = true
            if o.object isa CER
                o.object.pubpoint = String(copy(access_description[2].tag.value))
            end
        end
        if access_description[1].tag.value == @oid "1.3.6.1.5.5.7.48.10"
            tpi.nicenames && (access_description[1].nicename = "rpkiManifest")
            manifest_present = true
            if o.object isa CER
                o.object.manifest = String(copy(access_description[2].tag.value))
            end
        end
        if access_description[1].tag.value == @oid "1.3.6.1.5.5.7.48.13"
            tpi.nicenames && (access_description[1].nicename = "rpkiNotify")
            if o.object isa CER
                o.object.rrdp_notify = String(copy(access_description[2].tag.value))
            end
        end
    end
    if o.object isa CER
        if !carepo_present
            remark_ASN1Error!(node, "missing essential caRepository")
        end
        if !manifest_present
            remark_ASN1Error!(node, "missing essential rpkiManifest")
        end
    end
end


@check "ipAddrBlocks" begin
AFI_v4 = 0x01
AFI_v6 = 0x02
    DER.parse_append!(DER.Buf(node.tag.value), node)
    node.validated = true
    check_tag(node[1], ASN1.SEQUENCE)
    for ipaddrblock in node[1].children 
        check_tag(ipaddrblock, ASN1.SEQUENCE)
        check_tag(ipaddrblock[1], ASN1.OCTETSTRING)
        afi = ipaddrblock[1].tag.value[2]
        if afi != AFI_v6 && afi != AFI_v4
            @error "illegal AFI"
            remark_ASN1Error!(ipaddrblock, "Unknown AFI, not IPv6 or IPv4")
            return
        end

        #if typeof(ipaddrblock[2].tag) == Tag{ASN1.SEQUENCE}
        if istag(ipaddrblock[2].tag, ASN1.SEQUENCE)
            ipaddrblock[2].validated = true
            # now loop over children of this SEQUENCE OF IPAddressOrRange 
            for ipaddress_or_range in ipaddrblock[2].children
                ipaddress_or_range.validated = true
                ipr = if istag(ipaddress_or_range.tag, ASN1.SEQUENCE)
                    # if child is another SEQUENCE, we have an IPAddressRange
                    # we expect two BITSTRINGs in this SEQUENCE
                    check_tag(ipaddress_or_range[1], ASN1.BITSTRING)
                    check_tag(ipaddress_or_range[2], ASN1.BITSTRING)
                    if afi == AFI_v6
                        bitstrings_to_v6range(
                         ipaddress_or_range[1].tag.value,
                         ipaddress_or_range[2].tag.value
                        )
                    elseif afi == AFI_v4
                        bitstrings_to_v4range(
                         ipaddress_or_range[1].tag.value,
                         ipaddress_or_range[2].tag.value
                        )
                    end
                elseif istag(ipaddress_or_range.tag, ASN1.BITSTRING)
                    # else if it is a BITSTRING, we have an IPAddress (prefix)
                    bitstring = ipaddress_or_range.tag.value
                    if afi == AFI_v6
                        bitstring_to_v6range(bitstring)
                    elseif afi == AFI_v4
                        bitstring_to_v4range(bitstring)
                    end
                else
                    remark_ASN1Issue!(ipaddress_or_range, "unexpected ASN1 tag")
                    @error "unexpected tag number $(ipaddress_or_range.tag.number)"
                    continue
                end
                add_resource!(o.object, ipr)
            end # for-loop over SEQUENCE OF IPAddressOrRange
            if o.object isa CER
                if afi == AFI_v6 
                    o.object.inherit_v6_prefixes = false
                elseif afi == AFI_v4
                    o.object.inherit_v4_prefixes = false
                end
            end
        elseif istag(ipaddrblock[2].tag, ASN1.NULL)
            if o.object isa CER
                if afi == AFI_v6 
                    o.object.inherit_v6_prefixes = true
                elseif afi == AFI_v4
                    o.object.inherit_v4_prefixes = true
                end
            end
        else
            remark_ASN1Issue!(ipaddrblock[2], "expected either SEQUENCE OF or NULL here")
        end

    end
end

@check "autonomousSysIds" begin
    DER.parse_append!(DER.Buf(node.tag.value), node)
    node.validated = true
    check_tag(node[1], ASN1.SEQUENCE)
    for asidentifierchoice in node[1].children 
        # expect either a [0] or [1]
        #check_tag(asidentifierchoice, ASN1.CONTEXT_SPECIFIC)
        check_contextspecific(asidentifierchoice)
        if asidentifierchoice.tag.number == ASN1.Tagnumber(0)
            #DER.parse_append!(DER.Buf(asidentifierchoice.tag.value), asidentifierchoice)
            # or NULL (inherit) or SEQUENCE OF ASIdOrRange
            if istag(asidentifierchoice[1].tag, ASN1.NULL)
                if o.object isa CER
                    o.object.inherit_ASNs = true
                end
                #throw("implement inherit for ASIdentifierChoice")
            elseif istag(asidentifierchoice[1].tag, ASN1.SEQUENCE)
                # now it can be or a single INTEGER, or again a SEQUENCE
                asidentifierchoice[1].validated = true
                if o.object isa CER
                    o.object.inherit_ASNs = false
                end
                for asid_or_range in asidentifierchoice[1].children
                    if istag(asid_or_range.tag, ASN1.INTEGER)
                        asid = UInt32(ASN1.value(asid_or_range.tag))
                        push!(o.object.ASNs, AutSysNum(asid))
                        asid_or_range.validated = true
                    elseif istag(asid_or_range.tag, ASN1.SEQUENCE)
                        asmin = UInt32(ASN1.value(asid_or_range[1].tag))
                        asmax = UInt32(ASN1.value(asid_or_range[2].tag))
                        push!(o.object.ASNs, AutSysNumRange(asmin, asmax))
                        asid_or_range.validated = true
                        asid_or_range[1].validated = true
                        asid_or_range[2].validated = true
                    else
                        remark_ASN1Issue!(asid_or_range[1], "unexpected tag number $(asid_or_range[1].tag.number)")
                    end
                end #for-loop asid_or_range
            else
                remark_ASN1Issue!(asidentifierchoice[1], "expected either a SEQUENCE OF or a NULL here")
            end

        elseif asidentifierchoice.tag.number == ASN1.Tagnumber(1)
            throw("implement rdi for ASIdentifierChoice")
        else
            remark_ASN1Error!(asidentifierchoice, "Unknown Context-Specific tag number, expecting 0 or 1")
        end
    end
end

@check "subjectKeyIdentifier" begin
    # second pass
    DER.parse_append!(DER.Buf(node.tag.value), node)
    if o.object isa CER
        o.object.ski = node[1].tag.value
    elseif o.object isa Union{MFT,ROA}
        tpi.ee_ski = node[1].tag.value
    end
    if tpi.nicenames
        node[1].nicevalue = bytes2hex(node[1].tag.value)
    end
end

@check "certificatePolicies" begin
    # second pass
    DER.parse_append!(DER.Buf(node.tag.value), node)
    check_tag(node[1], ASN1.SEQUENCE)
    for c in node[1].children
        check_tag(c, ASN1.SEQUENCE)
        check_tag(c[1], ASN1.OID)
        if tpi.nicenames
            c[1].nicevalue = oid_to_str(c[1].tag.value)
        end
    end
end

@check "basicConstraints" begin
    # second pass
    DER.parse_append!(DER.Buf(node.tag.value), node)
    check_tag(node[1], ASN1.SEQUENCE)
    check_tag(node[1,1], ASN1.BOOLEAN)
    if tpi.nicenames
        node[1,1].nicename = "cA"
    end
end

@check "keyUsage" begin
    # second pass
    DER.parse_append!(DER.Buf(node.tag.value), node)
    check_tag(node, ASN1.OCTETSTRING)
    check_tag(node[1], ASN1.BITSTRING)
    if tpi.nicenames
        node[1].nicevalue = ASN1.value(node[1].tag)
    end
end

@check "cRLDistributionPoints" begin
    # second pass
    DER.parse_append!(DER.Buf(node.tag.value), node)
    check_tag(node[1], ASN1.SEQUENCE)
    for c in node[1].children
        check_tag(c, ASN1.SEQUENCE)
        check_contextspecific(c[1])
        if c[1].tag.number == ASN1.Tagnumber(0)
            #distributionPoint
            if c[1,1].tag.number == ASN1.Tagnumber(0)
                #fullName
                if c[1,1,1].tag.number == ASN1.Tagnumber(6)
                    # uniformResourceIdentifier
                    if tpi.nicenames
                        c[1,1,1].nicevalue = String(copy(c[1,1,1].tag.value))
                    end
                end
            end
        end
    end
end

@check "authorityInfoAccess" begin
    DER.parse_append!(DER.Buf(node.tag.value), node)
    check_tag(node[1], ASN1.SEQUENCE)
    for c in node[1].children
        check_tag(c, ASN1.SEQUENCE)
        # expecting 1.3.6.1.5.5.7.48.2 == id-ad-caIssuers
        check_OID(c[1], @oid("1.3.6.1.5.5.7.48.2"))
        check_contextspecific(c[2])
        if tpi.nicenames
            c[2].nicevalue = String(copy(c[2].tag.value))
        end
    end
end

@check "authorityKeyIdentifier" begin
    # second pass
    DER.parse_append!(DER.Buf(node.tag.value), node)
    check_tag(node[1], ASN1.SEQUENCE)
    check_contextspecific(node[1,1])
    if o.object isa CER
        o.object.aki = node[1,1].tag.value
        if !tpi.oneshot
            if isempty(tpi.certStack)
                if o.object.selfsigned != true
                    @warn "Expected self-signed certificate: $(o.filename)"
                end
                if !isempty(o.object.ski)
                    if o.object.ski != o.object.aki
                        @warn "Expected ski == aki for $(o.filename)"
                        remark_ASN1Error!(o, "authorityKeyIdentifier and subjectKeyIdentifier
                                          present on this (expected to be self-signed)
                                          certificate, but they do not match")
                        remark_ASN1Error!(node, "authorityKeyIdentifier and subjectKeyIdentifier
                                          present on this (expected to be self-signed)
                                          certificate, but they do not match")
                    end
                else
                    @warn "Unexpected empty ski for $(o.filename)"
                end
            elseif o.object.aki != tpi.certStack[end].ski
                @warn "CER aki ski mismatch"
                remark_ASN1Error!(o, "authorityKeyIdentifier mismatch, expected
                                  $(bytes2hex(tpi.certStack[end].ski))")
                remark_ASN1Error!(node, "authorityKeyIdentifier mismatch, expected
                                  $(bytes2hex(tpi.certStack[end].ski))")
            end
        end
    elseif o.object isa Union{MFT,ROA}
        tpi.ee_aki = node[1,1].tag.value
        if !tpi.oneshot
            if !isempty(tpi.certStack)
                if tpi.ee_aki != tpi.certStack[end].ski
                    @error "EE aki ski mismatch in $(o.filename)"
                    remark_ASN1Error!(o, "EE aki ski mismatch, expected
                                      $(bytes2hex(tpi.certStack[end].ski))")
                    remark_ASN1Error!(node, "EE aki ski mismatch, expected
                                      $(bytes2hex(tpi.certStack[end].ski))")
                end
            else
                @debug "empty certStack, is this a check_ASN1 out of process_tas?"
            end
        end
    end
    if tpi.nicenames
        node[1,1].nicevalue = bytes2hex(node[1,1].tag.value)
    end
end

function check_ASN1_extension(oid::Vector{UInt8}, o::RPKIObject{T}, node::ASN1.Node, tpi::TmpParseInfo) where T
    if oid == @oid("1.3.6.1.5.5.7.1.11")
        check_ASN1_subjectInfoAccess(o, node, tpi)
    elseif oid == @oid("1.3.6.1.5.5.7.1.7")
        check_ASN1_ipAddrBlocks(o, node, tpi)
    elseif oid == @oid("1.3.6.1.5.5.7.1.8")
        check_ASN1_autonomousSysIds(o, node, tpi)
    elseif oid == @oid("2.5.29.14")
        check_ASN1_subjectKeyIdentifier(o, node, tpi)
    elseif oid == @oid("2.5.29.32")
        check_ASN1_certificatePolicies(o, node, tpi)
    elseif oid == @oid("2.5.29.19")
        check_ASN1_basicConstraints(o, node, tpi)
    elseif oid == @oid("2.5.29.15")
        check_ASN1_keyUsage(o, node, tpi)
    elseif oid == @oid("2.5.29.31")
        check_ASN1_cRLDistributionPoints(o, node, tpi)
    elseif oid == @oid("1.3.6.1.5.5.7.1.1")
        check_ASN1_authorityInfoAccess(o, node, tpi)
    elseif oid == @oid("2.5.29.35")
        check_ASN1_authorityKeyIdentifier(o, node, tpi)
    else
        @warn "Unknown oid $(oid_to_str(oid)) passed to X509::check_extension" maxlog=10
        remark_ASN1Issue!(node, "Unknown extension")
    end

end

@check "version"  begin
    # Version == 0x02? (meaning version 3)
    check_contextspecific(node, 0x00)
    check_value(node[1], ASN1.INTEGER, 0x02)
    if tpi.nicenames
        node.nicevalue = string(ASN1.value(node[1].tag))
    end
end

@check "serialNumber" begin
    check_tag(node, ASN1.INTEGER)
    # do we need the serial? 
    if o.object isa CER
        o.object.serial = ASN1.value(node.tag, force_reinterpret=true)
    end
    if tpi.nicenames 
        node.nicevalue = string(ASN1.value(node.tag, force_reinterpret=true))
    end
end

@check "signature" begin
    check_tag(node, ASN1.SEQUENCE)

    #tag_OID(node[1], @oid "1.2.840.113549.1.1.11") # sha256WithRSAEncryption
    check_OID(node[1], @oid "1.2.840.113549.1.1.11") # sha256WithRSAEncryption
    if tpi.nicenames
        node[1].nicevalue = oid_to_str(node[1].tag.value)
    end
    # here, the parameters MUST be present and MUST be NULL (RFC4055)
    if childcount(node, 2)
        check_tag(node[2], ASN1.NULL) # TODO be more explicit in the remark
    end
end

@check "issuer" begin
    # Issuer = Name = RDNSequence = SEQUENCE OF RelativeDistinguishedName
    check_tag(node, ASN1.SEQUENCE)
    issuer_set = node[1]
    check_tag(issuer_set, ASN1.SET)
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

    childcount(issuer_set, 1:2)
    # If the issuer contains the serialNumber as well,
    # the set should contain 1 child, the RECOMMENDED set
    # TODO check this interpretation
    issuer = check_attribute(issuer_set, @oid("2.5.4.3"), ASN1.PRINTABLESTRING, [ASN1.UTF8STRING])
    if !isnothing(issuer)
        if o.object isa CER
            o.object.issuer = ASN1.value(issuer.tag)
        end
        if tpi.nicenames
            node.nicevalue = ASN1.value(issuer.tag)
        end
    else
        @warn("no issuer for $(o.filename)")
    end

	if length(issuer_set.children) > 1
	    # if size == 2, the second thing must be a CertificateSerialNumber
        @error "TODO: serialNumber in Issuer"
    end
end

@check "validity" begin
    # SEQUENCE of 2x Time, which is a CHOICE of utcTime/generalTime
    check_tag(node, ASN1.SEQUENCE)
    check_tag(node[1], [ASN1.UTCTIME, ASN1.GENTIME])
    check_tag(node[2], [ASN1.UTCTIME, ASN1.GENTIME])
    if o.object isa CER
        o.object.notBefore = ASN1.value(node[1].tag)
        o.object.notAfter = ASN1.value(node[2].tag)
    end
    if tpi.nicenames
        node[1].nicename = "notBefore"
        node[1].nicevalue = string(ASN1.value(node[1].tag))
        node[2].nicename = "notAfter"
        node[2].nicevalue = string(ASN1.value(node[2].tag))

    end
end

@check "subject" begin
    check_tag(node, ASN1.SEQUENCE)
    # RFC6487:
    #  Each distinct subordinate CA and
    #  EE certified by the issuer MUST be identified using a subject name
    #  that is unique per issuer.
    #  TODO can we check on this? not here, but in a later stage?
    subject = check_attribute(node[1], @oid("2.5.4.3"), ASN1.PRINTABLESTRING, [ASN1.UTF8STRING])
    #@debug "CER, subject:" ASN1.value(subject.tag)

    if tpi.nicenames
        node.nicevalue = ASN1.value(subject.tag)
    end
    if o.object isa CER
        o.object.subject = ASN1.value(subject.tag)
        o.object.selfsigned = o.object.issuer == o.object.subject
    end
end

@check "algorithm" begin
    check_tag(node, ASN1.SEQUENCE)
    # FIXME: RFC6485 is not quite clear on which OID we should expect here..
    check_OID(node[1], @oid "1.2.840.113549.1.1.1")
    check_tag(node[2], ASN1.NULL)
    if tpi.nicenames
        node[1].nicevalue = oid_to_str(node[1].tag.value)
    end
end

@check "subjectPublicKey" begin
    check_tag(node, ASN1.BITSTRING)

    # Now we go for a second pass:
    # skip the first byte as it will be 0, 
    # indicating the number if unused bits in the last byte
    
    encaps_buf = DER.Buf(node.tag.value[2:end])
    DER.parse_append!(encaps_buf, node)

    check_tag(node[1], ASN1.SEQUENCE)
    check_tag(node[1,1], ASN1.INTEGER)
   
    encaps_modulus  = node[1, 1]
    encaps_exponent = node[1, 2]
    # RFC6485:the exponent MUST be 65537
    check_value(encaps_exponent, ASN1.INTEGER, 65_537)

    # 256 bytes + the first byte indicating unused bits == 257
    @assert encaps_modulus.tag.len == 257
    if o.object isa CER
        o.object.rsa_modulus   = to_bigint(@view encaps_modulus.tag.value[2:end])
        o.object.rsa_exp       = ASN1.value(encaps_exponent.tag)
    end
    if o.object isa ROA || o.object isa MFT
        tpi.ee_rsaExponent = encaps_exponent
        tpi.ee_rsaModulus = encaps_modulus
    end
end

@check "subjectPublicKeyInfo" begin
    # AlgorithmIdentifier + BITSTRING
    check_tag(node, ASN1.SEQUENCE)
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
    check_contextspecific(node, 0x03)

    #mandatory_extensions = Vector{Vector{UInt8}}()

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
    #push!(mandatory_extensions, @oid "2.5.29.14")

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
    #push!(mandatory_extensions, @oid "2.5.29.15")

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
    #push!(mandatory_extensions, @oid "1.3.6.1.5.5.7.1.11")
    ### MUST have an caRepository (OID 1.3.6.1.5.5.7.48.5)
    ### MUST have a rpkiManifest (OID 1.3.6.1.5.5.7.48.10) pointing to an rsync uri
    # TODO rrdp stuff is in another RFC
    
    ## SIA for EE Certificates MUST be present, MUST be non-critical
    # MUST contain 1.3.6.1.5.5.7.48.11 signedObject pointing to rsync uri
    # for the signedObject

    # Certificate Policies MUST present+critical
    # MUST contain one policy, RFC6484
    # 2.5.29.32 certificatePolicies
    #push!(mandatory_extensions, @oid "2.5.29.32")
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

@check "signatureAlgorithm" begin
    # equal to @check "signature"
   
    check_tag(node, ASN1.SEQUENCE)

    check_OID(node[1], @oid "1.2.840.113549.1.1.11") # sha256WithRSAEncryption
    if tpi.nicenames
        node[1].nicevalue = oid_to_str(node[1].tag.value)
    end
    # here, the parameters MUST be present and MUST be NULL (RFC4055)
    if childcount(node, 2)
        check_tag(node[2], ASN1.NULL)
    end
end

@check "signatureValue" begin
    check_tag(node, ASN1.BITSTRING)
end


end # end module
