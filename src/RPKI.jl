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

function tagisa(node::Node, t::Type)
    if !(node.tag isa Tag{t})
        remark!(node, "expected this to be a $(nameof(t))")
    end
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


function check(o::RPKIObject{CER}) :: RPKIObject
    @debug "check CER"
    # The certificate should consist of three parts: (RFC5280)
	# Certificate  ::=  SEQUENCE  {
	#      tbsCertificate       TBSCertificate,
	#      signatureAlgorithm   AlgorithmIdentifier,
	#      signature            BIT STRING  }
    
    #checkchildren(o.tree, 3) # alternative to the popfirst! below
    nodes = ASN.iter(o.tree)
    checkchildren(popfirst!(nodes), 3)

    # First of the three is the TBSCertificate
    tagisa(popfirst!(nodes), ASN.SEQUENCE)
    # Version == 0x02? (meaning version 3)
    tagisa(popfirst!(nodes), ASN.RESERVED_ENC)
    tagvalue(popfirst!(nodes), ASN.INTEGER, 0x02) 
    # Serial number
    tagisa(popfirst!(nodes), ASN.INTEGER) #TODO must be positive and unique, RFC6487
    # Signature AlgorithmIdentifier
    tagisa(popfirst!(nodes), ASN.SEQUENCE)
    # OID must be RSA with SHA256 (RFC6485)
    tagvalue(popfirst!(nodes), ASN.OID, "1.2.840.113549.1.1.11")
    # parameters MUST be present and MUST be NULL (RFC4055):
    tagisa(popfirst!(nodes), ASN.NULL)

    # issuer = Name = RDNSequence = SEQUENCE OF RelativeDistinguishedName
    tagisa(popfirst!(nodes), ASN.SEQUENCE)
	issuer = popfirst!(nodes)
    tagisa(issuer, ASN.SET) 
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
	# check SET is of size 1 or 2
	checkchildren(issuer, 1:2)
	if length(issuer.children) > 1
		# if size > 1, is it a SET?
	    # because it is DER,
        # they must be ordered specifically TODO check x.690
    	tagisa(popfirst!(nodes), ASN.SET)
	else
		popfirst!(nodes) # should we check this being a SEQUENCE?

	end
	# check whether it contains CommonName of PrintableString
    #childrencontainvalue(issuer, ASN.OID, "2.5.4.3")
    containAttributeTypeAndValue(issuer, "2.5.4.3", ASN.PRINTABLESTRING)
	if length(issuer.children) > 1
	    # if size == 2, the second thing must be a CertificateSerialNumber
        childrencontain(issuer, ASN.INTEGER)
    end




     
    
    o
end
function check(::RPKIObject{T}) where {T}
    @warn "unknown RPKIObject type"
end

end # module
