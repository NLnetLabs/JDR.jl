using IPNets
using Sockets
export tagvalue, tagisa, tag_OID, tag_OIDs, childcount, containAttributeTypeAndValue
export tagis_contextspecific, check_extensions, get_extensions
export to_bigint
export bitstring_to_v4range, bitstring_to_v6range
export bitstrings_to_v4range, bitstrings_to_v6range


export istag

export check_contextspecific,
    check_tag,
    check_value,
    check_OID,
    check_attribute

# TODO implement optional custom remark::String
#function tagisa(node::Node, t::Type)
function check_tag(node::Node, tagnum::Tagnumber)
    if !(istag(node.tag, tagnum))
        remark_ASN1Issue!(node, "expected this to be a $(nameof(t))")
        false
    else
        node.validated = true
    end
end

function check_tag(node::Node, ts::Vector{Tagnumber})
    for t in ts
        if istag(node.tag, t)
            node.validated = true
            return
        end
    end
    remark_ASN1Issue!(node, "unexpected type $(nameof(typeof(node.tag).parameters[1]))")
end

function check_contextspecific(node::Node, tagnum::Union{Nothing, Tagnumber}=nothing)
    if !iscontextspecific(node.tag)
        if !isnothing(tagnum) && istag(node.tag, tagnum)
            remark_ASN1Issue!(node, "expected this to be a Context-Specific $(tagnum)")
        else
            remark_ASN1Issue!(node, "expected this to be a Context-Specific tag")
        end
    else
        node.validated = true
    end
end


function tagisa(node::Node, ts::Vector{DataType})
    for t in ts
        if node.tag isa Tag{t}
            node.validated = true
            return
        end
    end
    remark_ASN1Issue!(node, "unexpected type $(nameof(typeof(node.tag).parameters[1]))")
end

#function tagvalue(node::Node, t::Type, v::Any)
function check_value(node::Node, t::Tagnumber, v::Any)
    istag(node.tag, t)
    if !(ASN.value(node.tag) == v)
        remark_ASN1Issue!(node, "expected value to be '$(v)', got '$(ASN.value(node.tag))'")
    end
end

function check_OID(node::Node, v::Vector{UInt8})
    check_tag(node, ASN.OID)
    if !(node.tag.value == v)
        remark_ASN1Issue!(node, "expected OID to be '$(oid_to_str(v))', got $(oid_to_str(node.tag.value))")
        #@warn "expected OID to be '$(v)', got $(ASN.value(node.tag))"
    end
end

function tag_OIDs(node::Node, oids::Vector{Vector{UInt8}})
    tagisa(node, ASN.OID)
    for oid in oids 
        if (node.tag.value == oid)
            return
        end
    end
    remark_ASN1Issue!(node, "unexpected OID, expecting one of: $(join(oid_to_str.(oids), ", "))")
end


function childcount(node::Node, num::Integer) :: Bool #TODO can we use "> 1" here? maybe with an Expr?
    valid = true
    if !(length(node.children) == num)
        remark_ASN1Issue!(node, "expected $(num) children, found $(length(node.children))")
        valid = false
    end
    node.validated = true
    valid
end
function childcount(node::Node, range::UnitRange{Int}) #TODO can we use "> 1" here? maybe with an Expr?
    if !(length(node.children) in range)
        remark_ASN1Issue!(node, "expected $(minimum(range)) to $(maximum(range)) children, found $(length(node.children))")
    end
    node.validated = true
end


function childrencontain(node::Node, t::Type)
    found = false
    for c in ASN.iter(node)
        if c.tag isa Tag{t}
            found = true
        end
    end
    if !found
        remark_ASN1Issue!(node, "expected child node of type $(nameof(t))")
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
        remark_ASN1Issue!(node, "expected child node of type $(nameof(t)) and value $(v)")
    end
end

"""
    check_attribute (and TypeAndValue)

Checks: TODO

Returns: TODO

"""
function check_attribute(node::Node, oid::Vector{UInt8}, expected_type::Tagnumber, accepted_types::Vector{Tagnumber}=[]) :: Union{Nothing, Node}
    node.validated = true # this node is the RelativeDistinguishedName, thus a SET

    # in case of IMPLICITly tagged context-specific SETs, the first part of the
    # following @assert condition fails

    @assert istag(node.tag, ASN.SET) || istag(node.tag, CONTEXT_SPECIFIC)

    for c in node.children # every c in a SEQUENCE
        @assert istag(c.tag, ASN.SEQUENCE)
        if istag(c[1].tag, ASN.OID) && c[1].tag.value == oid
            if istag(c[2].tag, expected_type)
                c.validated = c[1].validated = c[2].validated = true
                return c[2]
            end
            for t in accepted_types
                if istag(c[2].tag, t)
                    c.validated = c[1].validated = c[2].validated = true
                    remark_ASN1Issue!(c[2], "RFC6487: MUST be PRINTABLESTRING instead of $(t)")
                    return c[2]
                end
            end

        end
    end
    remark_ASN1Issue!(node, "expected child node OID $(oid)")
    nothing
end

function check_extensions(tree::Node, oids::Vector{Pair{Vector{UInt8},String}}) 
    oids_found = get_extension_oids(tree)
    for (oid, nicename) in oids
        if !(oid in oids_found)
            remark_ASN1Issue!(tree, "expected Extension '$(nicename)' with OID $(oid)")
        end
    end
end

function get_extension_oids(tree::Node) :: Vector{Vector{UInt8}}
    check_tag(tree[1], ASN.SEQUENCE)

    oids_found = Vector{Vector{UInt8}}()
    for c in tree[1].children
        check_tag(c, ASN.SEQUENCE)
        check_tag(c[1], ASN.OID)
        #push!(oids_found, ASN.value(c[1].tag))
        push!(oids_found, c[1].tag.value)
    end
    oids_found
end

function get_extensions(tree::Node) :: Dict{Vector{UInt8},Node}
    check_tag(tree[1], ASN.SEQUENCE)

    extensions = Dict{Vector{UInt8},Node}()
    for c in tree[1].children
        check_tag(c, ASN.SEQUENCE)
        check_tag(c[1], ASN.OID)
        critical = false
        extension_octetstring = nothing
        if length(c.children) == 3
            check_value(c[2], ASN.BOOLEAN, true)
            critical = true
            extension_octetstring = c[3]
        else
            extension_octetstring = c[2]
        end
                                           
        #extensions[ASN.value(c[1].tag)] = extension_octetstring
        extensions[c[1].tag.value] = extension_octetstring
    end
    extensions
end

function bitstring_to_v4range(raw::Vector{UInt8}) :: IPRange{IPv4}
    # first byte of raw is the unused_bits byte
    # an empty BITSTRING is indicated by the unused_bits == 0x00
    # and no subsequent bytes
    if length(raw) == 1
        @assert raw[1] == 0x00
        return IPRange("0.0.0.0/0")
    end
    unused = raw[1]
    numbytes = length(raw) - 1 - 1
    bits = numbytes*8 + (8 - unused)
    addr =  @inbounds if length(raw) - 1 == 4
                reinterpret(UInt32, [raw[5], raw[4], raw[3], raw[2]])[1]
            elseif length(raw) - 1 == 3
                reinterpret(UInt32, [raw[4], raw[3], raw[2], 0x00])[1]
            elseif length(raw) - 1 == 2
                reinterpret(UInt32, [raw[3], raw[2], 0x00, 0x00])[1]
            elseif length(raw) - 1 == 1
                UInt32(raw[2])
            end >> unused

    IPRange(IPv4(addr << (32 - bits)), bits)
end

function bitstring_to_v6range(raw::Vector{UInt8}) :: IPRange{IPv6}
    # first byte of raw is the unused_bits byte
    # an empty BITSTRING is indicated by the unused_bits == 0x00
    # and no subsequent bytes
    if length(raw) == 1
        @assert raw[1] == 0x00
        return IPRange("::/0")
    end
    unused = raw[1]
    numbytes = length(raw) - 1 - 1
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt128, resize!(reverse(raw[2:end]), 16)))[1] >> unused
    IPRange(IPv6(addr << (128 - bits)), bits)
end

function bitstrings_to_v4range(raw_min::Vector{UInt8}, raw_max::Vector{UInt8}) :: IPRange{IPv4}
    #min_addr:
    unused = raw_min[1]
    numbytes = length(raw_min) - 1 - 1 # -1 unused byte, -1 because we correct for it in `bits =` below
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt32, resize!(reverse(raw_min[2:end]), 4)))[1] >> unused
    min_addr = addr << (32 - bits)

    #max_addr:
    unused = raw_max[1]
    numbytes = length(raw_max) - 1 - 1 # -1 unused byte, -1 because we correct for it in `bits =` below
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt32, resize!(reverse(raw_max[2:end]), 4)))[1] >> unused
    max_addr = (addr << (32 - bits)) | (0xffffffff >>> bits)

    IPRange(IPv4(min_addr), IPv4(max_addr))
end

function bitstrings_to_v6range(raw_min::Vector{UInt8}, raw_max::Vector{UInt8}) :: IPRange{IPv6}
    #min_addr:
    unused = raw_min[1]
    numbytes = length(raw_min) - 1 - 1 # -1 unused byte, -1 because we correct for it in `bits =` below
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt128, resize!(reverse(raw_min[2:end]), 16)))[1] >> unused
    min_addr = addr << (128 - bits)

    #max_addr:
    unused = raw_max[1]
    numbytes = length(raw_max) - 1 - 1 # -1 unused byte, -1 because we correct for it in `bits =` below
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt128, resize!(reverse(raw_max[2:end]), 16)))[1] >> unused
    max_addr = (addr << (128 - bits)) | ( (-1 % UInt128) >>> bits)

    IPRange(IPv6(min_addr), IPv6(max_addr))
end

function to_bigint(raw::Vector{UInt8}) :: BigInt
    @assert length(raw) % 16 == 0
    parse(BigInt, bytes2hex(raw), base=16)
end
