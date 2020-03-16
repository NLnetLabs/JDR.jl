module RPKI
using ..ASN
using ..DER

#abstract type RPKIObject <: AbstractNode end
struct RPKIObject{T}
    filename::String
    tree::Node
end
struct CER end # <: RPKIObject end 
struct MFT end # <: RPKIObject end 
struct CRL end # <: RPKIObject end 
struct ROA end # <: RPKIObject end 

function RPKIObject(filename::String)::RPKIObject
    tree = DER.parse_file_recursive(filename)
    ext = lowercase(splitext(filename)[2])
    if      ext == ".cer" RPKIObject{CER}(filename, tree)
    elseif  ext == ".mft" RPKIObject{MFT}(filename, tree)
    end
end

# TODO implement optional custom remark::String
function tagisa(node::Node, t::Type)
    if !(node.tag isa Tag{t})
        remark!(node, "expected this to be a $(nameof(t))")
    end
end
function tagis_contextspecific(node::Node, tagnum::UInt8)
    if !(node.tag isa Tag{ASN.CONTEXT_SPECIFIC} && node.tag.number == tagnum)
        remark!(node, "expected this to be a Context-Specific tag number $(tagnum)")
    end
end
function tagisa(node::Node, ts::Vector{DataType})
    for t in ts
        if node.tag isa Tag{t}
            return
        end
    end
    #remark!(node, "expected this to be a $(nameof(t))")
    remark!(node, "unexpected type $(nameof(typeof(node.tag).parameters[1]))")
end

function tagvalue(node::Node, t::Type, v::Any)
    tagisa(node, t)
    if !(ASN.value(node.tag) == v)
        remark!(node, "expected value to be '$(v)', got '$(ASN.value(node.tag))'")
    end
end

function checkchildren(node::Node, num::Integer) #TODO can we use "> 1" here? maybe with an Expr?
    if !(length(node.children) == num)
        remark!(node, "expected $(num) children, found $(length(node.children))")
    end
end
function checkchildren(node::Node, range::UnitRange{Int}) #TODO can we use "> 1" here? maybe with an Expr?
    if !(length(node.children) in range)
        remark!(node, "expected $(minimum(range)) to $(maximum(range)) children, found $(length(node.children))")
    end
end


function childrencontain(node::Node, t::Type)
    found = false
    for c in ASN.iter(node)
        if c.tag isa Tag{t}
            found = true
        end
    end
    if !found
        remark!(node, "expected child node of type $(nameof(t))")
    end
end

function childrencontainvalue(node::Node, t::Type, v::Any)
    found = false
    for c in ASN.iter(node)
        if c.tag isa Tag{t} && ASN.value(c.tag) == v
            found = true
        end
    end
    if !found
        remark!(node, "expected child node of type $(nameof(t)) and value $(v)")
    end
end

function containAttributeTypeAndValue(node::Node, oid::String, t::Type)
    found_oid = false
    for c in ASN.iter(node)
        if found_oid
            tagisa(c, t)
            break
        end
        if c.tag isa Tag{ASN.OID} && ASN.value(c.tag) == oid
            found_oid = true
        end
    end
    if !found_oid
        remark!(node, "expected child node OID $(oid)")
    end
end

function checkTbsCertificate(tree::Node)
    #TODO can we do some funky multilevel indexing
    # like chd[1][2] to get the second grandchild of the first child?

    chd = tree.children

    # Version == 0x02? (meaning version 3)
    #tagisa(chd[1], ASN.RESERVED_ENC)
    tagis_contextspecific(chd[1], 0x0)
    DER.parse_value!(chd[1])
    tagvalue(chd[1].children[1], ASN.INTEGER, 0x02)
    #encaps_buf = DER.Buf(chd[7].children[2].tag.value[2:end])
    #DER.parse_append!(encaps_buf, chd[7].children[2])

    # Serial number
    tagisa(chd[2], ASN.INTEGER)

    # Signature AlgorithmIdentifier
    # SEQ / OID / NULL
    tagisa(chd[3], ASN.SEQUENCE)
    tagvalue(chd[3].children[1], ASN.OID, "1.2.840.113549.1.1.11")
    tagisa(chd[3].children[2], ASN.NULL)

    # Issuer = Name = RDNSequence = SEQUENCE OF RelativeDistinguishedName
    tagisa(chd[4], ASN.SEQUENCE)
    issuer_set = chd[4].children[1] 
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
    containAttributeTypeAndValue(issuer_set, "2.5.4.3", ASN.PRINTABLESTRING)
	if length(issuer_set.children) > 1
	    # if size == 2, the second thing must be a CertificateSerialNumber
        @error "TODO: serialNumber in Issuer"
    end
    
    # Validity
    # SEQUENCE of 2x Time, which is a CHOICE of utcTime/generalTime
    tagisa(chd[5], ASN.SEQUENCE)
    tagisa(chd[5].children[1], [ASN.UTCTIME, ASN.GENTIME])
    tagisa(chd[5].children[2], [ASN.UTCTIME, ASN.GENTIME])

    # Subject
    # RFC6487:
    #  Each distinct subordinate CA and
    #  EE certified by the issuer MUST be identified using a subject name
    #  that is unique per issuer.
    #  TODO can we check on this? not here, but in a later stage?
    containAttributeTypeAndValue(chd[6], "2.5.4.3", ASN.PRINTABLESTRING)

    # SubjectPublicKeyInfo
    # AlgorithmIdentifier + BITSTRING
    tagisa(chd[7], ASN.SEQUENCE)
    tagisa(chd[7].children[1], ASN.SEQUENCE)
    # FIXME: RFC6485 is not quite clear on which OID we should expect here..
    tagvalue(chd[7].children[1].children[1], ASN.OID, "1.2.840.113549.1.1.1")
    tagisa(chd[7].children[1].children[2], ASN.NULL)
    tagisa(chd[7].children[2], ASN.BITSTRING)
    # here we go for a second pass:
    # skip the first byte as it will be 0,
    #   indicating the number if unused bits in the last byte
    
    encaps_buf = DER.Buf(chd[7].children[2].tag.value[2:end])
    DER.parse_append!(encaps_buf, chd[7].children[2])
   
    encaps_modulus  = chd[7].children[2].children[1].children[1]
    encaps_exponent = chd[7].children[2].children[1].children[2]
    # RFC6485:the exponent MUST be 65537
    tagvalue(encaps_exponent, ASN.INTEGER, 65_537)


    # issuerUniqueID [1]
    # TODO

    # subjectUniqueID [2]
    # TODO

    # extensions [3]
    # MUST be present
    extensions = chd[8]
    tagis_contextspecific(extensions, 0x3)
    DER.parse_value!(extensions)

    # RFC 6487 4.8.1 unclear:
    #   'The issuer determines whether the "cA" boolean is set.'
    # if this extension is here, the value is always true?
    # so the boolean is actually sort of redundant?
    # because when the subject is not a CA, this extension MUST NOT be here
    
    # Subject Key Identifier, MUST appear
    check_extension(extensions, "2.5.29.14") # non-critical, 160bit SHA-1

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
	check_extension(extensions, "2.5.29.15") # critical, 1byte BITSTRING

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

end

function check(o::RPKIObject{CER}) :: RPKIObject
    @debug "check CER"
    # The certificate should consist of three parts: (RFC5280)
	# Certificate  ::=  SEQUENCE  {
	#      tbsCertificate       TBSCertificate,
	#      signatureAlgorithm   AlgorithmIdentifier,
	#      signature            BIT STRING  }
    
    #checkchildren(o.tree, 3) # alternative to the popfirst! below
    checkchildren(o.tree, 3)
    tbsCertificate = o.tree.children[1]
    checkTbsCertificate(tbsCertificate)

    
    o
end
function check(::RPKIObject{T}) where {T}
    @warn "unknown RPKIObject type"
end

end # module
