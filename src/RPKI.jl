module RPKI
using ..ASN
using ..DER
using IPNets

#abstract type RPKIObject <: AbstractNode end
struct RPKIObject{T}
    filename::String
    tree::Node
    object::T
end

mutable struct CER 
    prefixes::Vector{Union{IPNet, Tuple{IPNet, IPNet}}}
    ASNs::Vector{UInt32}
end # <: RPKIObject end 
CER() = CER([], [])

function RPKIObject{T}(filename::String, tree::Node) where T 
    RPKIObject{T}(filename, tree, T())
end

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

function checkchildren(node::Node, num::Integer) :: Bool #TODO can we use "> 1" here? maybe with an Expr?
    valid = true
    if !(length(node.children) == num)
        remark!(node, "expected $(num) children, found $(length(node.children))")
        valid = false
    end
    valid
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

function check_extensions(tree::Node, oids::Vector{String}) 
    oids_found = get_extension_oids(tree)
    for o in oids
        if !(o in oids_found)
            remark!(tree, "expected Extension with OID $(o)")
        end
    end
end

function get_extension_oids(tree::Node) :: Vector{String}
    tagisa(tree[1], ASN.SEQUENCE)

    oids_found = Vector{String}([])
    for c in tree[1].children
        tagisa(c, ASN.SEQUENCE)
        tagisa(c[1], ASN.OID)
        push!(oids_found, ASN.value(c[1].tag))
    end
    oids_found
end
function get_extensions(tree::Node) :: Dict{String,Node}
    tagisa(tree[1], ASN.SEQUENCE)

    extensions = Dict{String,Node}()
    for c in tree[1].children
        tagisa(c, ASN.SEQUENCE)
        tagisa(c[1], ASN.OID)
        critical = false
        extension_octetstring = nothing
        if length(c.children) == 3
            tagvalue(c[2], ASN.BOOLEAN, true)
            critical = true
            extension_octetstring = c[3]
        else
            extension_octetstring = c[2]
        end
                                           
        extensions[ASN.value(c[1].tag)] = extension_octetstring
    end
    extensions
end

function checkTbsCertificate(o::RPKIObject, tbscert::Node)
    # Version == 0x02? (meaning version 3)
    tagis_contextspecific(tbscert[1], 0x0)
    DER.parse_value!(tbscert[1])
    tagvalue(tbscert[1, 1], ASN.INTEGER, 0x02)

    # Serial number
    tagisa(tbscert[2], ASN.INTEGER)

    # Signature AlgorithmIdentifier
    # SEQ / OID / NULL
    tagisa(tbscert[3], ASN.SEQUENCE)

    tagvalue(tbscert[3, 1], ASN.OID, "1.2.840.113549.1.1.11")
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
    containAttributeTypeAndValue(issuer_set, "2.5.4.3", ASN.PRINTABLESTRING)
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
    containAttributeTypeAndValue(tbscert[6], "2.5.4.3", ASN.PRINTABLESTRING)

    # SubjectPublicKeyInfo
    # AlgorithmIdentifier + BITSTRING
    tagisa(tbscert[7], ASN.SEQUENCE)
    tagisa(tbscert[7, 1], ASN.SEQUENCE)
    # FIXME: RFC6485 is not quite clear on which OID we should expect here..
    tagvalue(tbscert[7, 1, 1], ASN.OID, "1.2.840.113549.1.1.1")
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
    DER.parse_value!(extensions)

    mandatory_extensions = Vector{String}()

    # RFC 6487 4.8.1 unclear:
    #   'The issuer determines whether the "cA" boolean is set.'
    # if this extension is here, the value is always true?
    # so the boolean is actually sort of redundant?
    # because when the subject is not a CA, this extension MUST NOT be here
    
    # Subject Key Identifier, MUST appear
    #check_extension(extensions, "2.5.29.14") # non-critical, 160bit SHA-1
    push!(mandatory_extensions, "2.5.29.14")

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
    push!(mandatory_extensions, "2.5.29.15")

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
    #
    # ipAddrBlocks
    # SEQUENCE OF IPAddressFamily
    # IPAddressFamily type is a SEQUENCE containing an addressFamily
    #    and ipAddressChoice element.
    #
    # TODO: if v4+v6 in one extension, v4 must come first
    #


    #extension_oids = get_extension_oids(extensions)
    check_extensions(extensions, mandatory_extensions)
    all_extensions = get_extensions(extensions)
    if "1.3.6.1.5.5.7.1.7" in keys(all_extensions)
        #@debug "got IP extension"
        subtree = all_extensions["1.3.6.1.5.5.7.1.7"]
        DER.parse_append!(DER.Buf(subtree.tag.value), subtree)
        tagisa(subtree[1], ASN.SEQUENCE)
        for ipaddrblock in subtree[1].children 
            tagisa(ipaddrblock, ASN.SEQUENCE)
            tagisa(ipaddrblock[1], ASN.OCTETSTRING)
            afi = reinterpret(UInt16, reverse(ipaddrblock[1].tag.value))[1]
            @assert afi in [1,2] # 1 == IPv4, 2 == IPv6
            # now, or a NULL -> inherit
            # or a SEQUENCE
            if typeof(ipaddrblock[2].tag) == Tag{ASN.SEQUENCE}
                if typeof(ipaddrblock[2, 1].tag) == Tag{ASN.SEQUENCE}
                    # if child is another SEQUENCE, we have an IPAddressRange
                    #throw("check me")

                    # we expect two BITSTRINGs in this SEQUENCE
                    tagisa(ipaddrblock[2, 1, 1], ASN.BITSTRING)
                    tagisa(ipaddrblock[2, 1, 2], ASN.BITSTRING)
                    if afi == 1
                        #@debug bitstring_to_v4prefix(ipaddrblock[2, 1, 1].tag.value)
                        #@debug bitstring_to_v4prefix(ipaddrblock[2, 1, 2].tag.value)
                        (minaddr, maxaddr) = bitstrings_to_v4range(
                                                ipaddrblock[2, 1, 1].tag.value,
                                                ipaddrblock[2, 1, 2].tag.value
                                              )
                        #@debug "got ", minaddr, maxaddr
                        push!(o.object.prefixes, (minaddr, maxaddr))
                    else
                        #throw(".cer with v6 range")
                        (minaddr, maxaddr) = bitstrings_to_v6range(
                                                ipaddrblock[2, 1, 1].tag.value,
                                                ipaddrblock[2, 1, 2].tag.value
                                              )
                        #@debug "got ", minaddr, maxaddr
                        push!(o.object.prefixes, (minaddr, maxaddr))

                    end
                elseif typeof(ipaddrblock[2, 1].tag) == Tag{ASN.BITSTRING}
                    # else if it is a BITSTRING, we have an IPAddress (prefix)
                    #@debug "IPAddress (prefix)"
                    bitstring = ipaddrblock[2, 1].tag.value
                    if afi == 1
                        push!(o.object.prefixes, bitstring_to_v4prefix(bitstring))
                    else
                        push!(o.object.prefixes, bitstring_to_v6prefix(bitstring))
                    end
                else
                    @error "unexpected tag"
                end
            else
                @error "implement inherit"
            end
        end
        #IP
    else
        @assert "1.3.6.1.5.5.7.1.8" in keys(all_extensions)
    end
    if "1.3.6.1.5.5.7.1.8" in keys(all_extensions)
        #@debug "got ASN extension"
    end

    # or:
    # get all extensions (so return the OIDs)
    # and create a check_extension(OID{TypeBasedOnOIDString})
end

function bitstring_to_v4prefix(raw::Vector{UInt8}) :: IPv4Net
    # first byte of raw is the unused_bits byte
    # an empty BITSTRING is indicated by the unused_bits == 0x00
    # and no subsequent bytes
    if length(raw) == 1
        @assert raw[1] == 0x00
        return IPv4Net(0,0)
    end
    unused = raw[1]
    numbytes = length(raw) - 1 - 1
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt32, resize!(reverse(raw[2:end]), 4)))[1] >> unused
    return IPv4Net(addr << (32 - bits), bits)
end

function bitstring_to_v6prefix(raw::Vector{UInt8}) :: IPv6Net
    # first byte of raw is the unused_bits byte
    # an empty BITSTRING is indicated by the unused_bits == 0x00
    # and no subsequent bytes
    if length(raw) == 1
        @assert raw[1] == 0x00
        return IPv6Net(0,0)
    end
    unused = raw[1]
    numbytes = length(raw) - 1 - 1
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt128, resize!(reverse(raw[2:end]), 16)))[1] >> unused
    return IPv6Net(addr << (128 - bits), bits)
end

function bitstrings_to_v4range(raw_min::Vector{UInt8}, raw_max::Vector{UInt8})
    #min_addr:
    unused = raw_min[1]
    numbytes = length(raw_min) - 1 - 1 # -1 unused byte, -1 because we correct for it in `bits =` below
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt32, resize!(reverse(raw_min[2:end]), 4)))[1] >> unused
    min_addr = IPv4Net(addr << (32 - bits), 32)

    #max_addr:
    unused = raw_max[1]
    numbytes = length(raw_max) - 1 - 1 # -1 unused byte, -1 because we correct for it in `bits =` below
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt32, resize!(reverse(raw_max[2:end]), 4)))[1] >> unused
    max_addr = (addr << (32 - bits)) | (0xffffffff >>> bits)
    max_addr = IPv4Net(max_addr, 32)

    (min_addr, max_addr)
end

function bitstrings_to_v6range(raw_min::Vector{UInt8}, raw_max::Vector{UInt8})
    #min_addr:
    unused = raw_min[1]
    numbytes = length(raw_min) - 1 - 1 # -1 unused byte, -1 because we correct for it in `bits =` below
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt128, resize!(reverse(raw_min[2:end]), 16)))[1] >> unused
    min_addr = IPv6Net(addr << (128 - bits), 128)

    #max_addr:
    unused = raw_max[1]
    numbytes = length(raw_max) - 1 - 1 # -1 unused byte, -1 because we correct for it in `bits =` below
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt128, resize!(reverse(raw_max[2:end]), 16)))[1] >> unused
    max_addr = (addr << (128 - bits)) | ( (-1 % UInt128) >>> bits)
    max_addr = IPv6Net(max_addr, 128)

    (min_addr, max_addr)
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
function check(::RPKIObject{T}) where {T}
    @warn "unknown RPKIObject type"
end

end # module
