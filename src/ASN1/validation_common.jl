using IPNets
export tagvalue, tagisa, tag_OID, childcount, containAttributeTypeAndValue
export tagis_contextspecific, check_extensions, get_extensions
export to_bigint, bitstring_to_v4prefix, bitstring_to_v6prefix
export bitstrings_to_v4range, bitstrings_to_v6range
export new_bitstring_to_v4prefix, new_bitstring_to_v6prefix, new_bitstrings_to_v4range, new_bitstrings_to_v6range

# TODO implement optional custom remark::String
function tagisa(node::Node, t::Type)
    if !(node.tag isa Tag{t})
        warn!(node, "expected this to be a $(nameof(t))")
        return false
    else
        return node.validated = true
    end
end
function tagis_contextspecific(node::Node, tagnum::UInt8)
    if !(node.tag isa Tag{ASN.CONTEXT_SPECIFIC} && node.tag.number == tagnum)
        warn!(node, "expected this to be a Context-Specific tag number $(tagnum)")
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
    warn!(node, "unexpected type $(nameof(typeof(node.tag).parameters[1]))")
end

function tagvalue(node::Node, t::Type, v::Any)
    tagisa(node, t)
    if !(ASN.value(node.tag) == v)
        warn!(node, "expected value to be '$(v)', got '$(ASN.value(node.tag))'")
    end
end

function tag_OID(node::Node, v::Vector{UInt8})
    tagisa(node, ASN.OID)
    if !(node.tag.value == v)
        remark_ASN1Issue!(node, "expected OID to be '$(oid_to_str(v))', got $(oid_to_str(node.tag.value))")
        #@warn "expected OID to be '$(v)', got $(ASN.value(node.tag))"
    end
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
        warn!(node, "expected $(minimum(range)) to $(maximum(range)) children, found $(length(node.children))")
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
        warn!(node, "expected child node of type $(nameof(t))")
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
        warn!(node, "expected child node of type $(nameof(t)) and value $(v)")
    end
end

function containAttributeTypeAndValue(node::Node, oid::Vector{UInt8}, expected_type::DataType, accepted_types::Vector{DataType}=[]) :: Union{Nothing, Node}
    node.validated = true # this node is the RelativeDistinguishedName, thus a SET

    # in case of IMPLICITly tagged context-specific SETs, the first part of the
    # following @assert condition fails
    @assert node.tag isa Tag{ASN.SET} || node.tag isa Tag{CONTEXT_SPECIFIC}

    for c in node.children # every c in a SEQUENCE
        @assert c.tag isa Tag{ASN.SEQUENCE}
        if c[1].tag isa Tag{ASN.OID} && c[1].tag.value == oid
            if c[2].tag isa Tag{expected_type}
                c.validated = c[1].validated = c[2].validated = true
                return c[2]
            end
            for t in accepted_types
                if c[2].tag isa Tag{t}
                    c.validated = c[1].validated = c[2].validated = true
                    remark_ASN1Issue!(c[2], "RFC6487: MUST be PRINTABLESTRING instead of $(t)")
                    return c[2]
                end
            end

        end
    end
    warn!(node, "expected child node OID $(oid)")
    nothing
end

function check_extensions(tree::Node, oids::Vector{Pair{Vector{UInt8},String}}) 
    oids_found = get_extension_oids(tree)
    for (oid, nicename) in oids
        if !(oid in oids_found)
            warn!(tree, "expected Extension '$(nicename)' with OID $(oid)")
        end
    end
end

function depr_check_extensions(tree::Node, oids::Vector{Vector{UInt8}}) 
    oids_found = get_extension_oids(tree)
    for o in oids
        if !(o in oids_found)
            warn!(tree, "expected Extension with OID $(o)")
        end
    end
end

#function get_extension_oids(tree::Node) :: Vector{String}
function get_extension_oids(tree::Node) :: Vector{Vector{UInt8}}
    tagisa(tree[1], ASN.SEQUENCE)

    oids_found = Vector{Vector{UInt8}}()
    for c in tree[1].children
        tagisa(c, ASN.SEQUENCE)
        tagisa(c[1], ASN.OID)
        #push!(oids_found, ASN.value(c[1].tag))
        push!(oids_found, c[1].tag.value)
    end
    oids_found
end

#function get_extensions(tree::Node) :: Dict{String,Node}
function get_extensions(tree::Node) :: Dict{Vector{UInt8},Node}
    tagisa(tree[1], ASN.SEQUENCE)

    extensions = Dict{Vector{UInt8},Node}()
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
                                           
        #extensions[ASN.value(c[1].tag)] = extension_octetstring
        extensions[c[1].tag.value] = extension_octetstring
    end
    extensions
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
    addr =  @inbounds if length(raw) - 1 == 4
                reinterpret(UInt32, [raw[5], raw[4], raw[3], raw[2]])[1]
            elseif length(raw) - 1 == 3
                reinterpret(UInt32, [raw[4], raw[3], raw[2], 0x00])[1]
            elseif length(raw) - 1 == 2
                reinterpret(UInt32, [raw[3], raw[2], 0x00, 0x00])[1]
            elseif length(raw) - 1 == 1
                UInt32(raw[2])
            end >> unused

    return IPv4Net(addr << (32 - bits), bits)
end
function new_bitstring_to_v4prefix(raw::Vector{UInt8}) :: Tuple{Integer,Integer}
    # first byte of raw is the unused_bits byte
    # an empty BITSTRING is indicated by the unused_bits == 0x00
    # and no subsequent bytes
    if length(raw) == 1
        @assert raw[1] == 0x00
        return (0, typemax(UInt32))
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

    #return IPv4Net(addr << (32 - bits), bits)
    (addr << (32 - bits), addr << (32 - bits) + typemax(UInt32) >> bits)
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
function new_bitstring_to_v6prefix(raw::Vector{UInt8}) :: Tuple{Integer, Integer}
    # first byte of raw is the unused_bits byte
    # an empty BITSTRING is indicated by the unused_bits == 0x00
    # and no subsequent bytes
    if length(raw) == 1
        @assert raw[1] == 0x00
        return (0, typemax(UInt128))
    end
    unused = raw[1]
    numbytes = length(raw) - 1 - 1
    bits = numbytes*8 + (8 - unused)
    addr = (reinterpret(UInt128, resize!(reverse(raw[2:end]), 16)))[1] >> unused
    #return IPv6Net(addr << (128 - bits), bits)
    (addr << (128 - bits), addr << (128 - bits) + typemax(UInt128) >> bits)
end

function bitstrings_to_v4range(raw_min::Vector{UInt8}, raw_max::Vector{UInt8}) :: Tuple{IPv4Net, IPv4Net}
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
function new_bitstrings_to_v4range(raw_min::Vector{UInt8}, raw_max::Vector{UInt8}) :: Tuple{Integer, Integer}
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

    (min_addr, max_addr)
end

function bitstrings_to_v6range(raw_min::Vector{UInt8}, raw_max::Vector{UInt8}) :: Tuple{IPv6Net, IPv6Net}
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

function new_bitstrings_to_v6range(raw_min::Vector{UInt8}, raw_max::Vector{UInt8}) :: Tuple{Integer, Integer}
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

    (min_addr, max_addr)
end

function to_bigint(raw::Vector{UInt8}) :: BigInt
    @assert length(raw) % 16 == 0
    parse(BigInt, bytes2hex(raw), base=16)
end
