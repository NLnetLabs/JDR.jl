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

function checkchildren(node::Node, num::Integer)
    if !(length(node.children) == num)
        remark!(node, "expected $(num) children, found $(length(node.children))")
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
    tagisa(popfirst!(nodes), ASN.INTEGER) #TODO must be positive and unique, rfc6487
    # Signature AlgorithmIdentifier 
    tagisa(popfirst!(nodes), ASN.SEQUENCE)
    tagvalue(popfirst!(nodes), ASN.OID, "1.2.840.113549.1.1.11")

    # next in ASN.1, as part of the AlgorithmIdentifier:
    #   parameters              ANY DEFINED BY algorithm OPTIONAL
    # is this the NULL in this part of the cert?

    
    o
end
function check(::RPKIObject{T}) where {T}
    @warn "unknown RPKIObject type"
end

end # module
