struct VRP{AFI<:IPNet}
    prefix::AFI
    maxlength::Integer
end

mutable struct ROA
    asid::Integer
    vrps::Vector{VRP}
    prefixes::Vector{Union{IPNet, Tuple{IPNet, IPNet}}}
    rsa_modulus::BigInt
    rsa_exp::Int
    local_eContent_hash::String
end
ROA() = ROA(0, [], [], 0, 0, "EMPTY_LOCAL_HASH")

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

macro check(name, block)
    fnname = Symbol("check_ASN1_$(name)")
    eval(quote
      function $fnname(o::RPKIObject{T}, node::Node, tpi::TmpParseInfo) where T
          if tpi.setNicenames
              node.nicename = $name
          end
          $block
      end
  end)
end

@check "version" begin
    tagis_contextspecific(node, 0x00)
    # EXPLICIT tagging, so the version node be in a child
    checkchildren(node, 1)
    tagisa(node[1], ASN.INTEGER)
    if value(node[1].tag) == 0
        info!(node[1], "version explicitly set to 0 while that is the default")
    end
end

@check "asID" begin
    tagisa(node, ASN.INTEGER)
    o.object.asid = ASN.value(node.tag)
end
@check "ROAIPAddress" begin
    tagisa(node, ASN.SEQUENCE)
    tagisa(node[1], ASN.BITSTRING)
    node[1].nicename = "address"

    prefix = if tpi.afi == 1
        bitstring_to_v4prefix(node[1].tag.value)
    elseif tpi.afi == 2
        bitstring_to_v6prefix(node[1].tag.value)
    else
        throw("illegal AFI in check_ASN1_ROAIPAddress")
    end

    maxlength = prefix.netmask #FIXME @code_warntype ?

    # optional maxLength:
    if length(node.children) == 2
        tagisa(node[2], ASN.INTEGER)
        node[2].nicename = "maxLength"
        #@assert node[2].tag.len == 1
        if node[2].tag.value[1] == maxlength
            info!(node[2], "redundant maxLength")
        else
            maxlength = node[2].tag.value[1]
        end
    end
    push!(o.object.vrps, VRP(prefix, maxlength))
end
@check "ROAIPAddressFamily" begin
        tagisa(node, ASN.SEQUENCE)
        # addressFamily
        tagisa(node[1], ASN.OCTETSTRING)

        tpi.afi = reinterpret(UInt16, reverse(node[1].tag.value))[1]
        if ! (tpi.afi in [1,2])
            @error "invalid AFI in ROA"
            err!(node[1], "addressFamily MUST be either 0002 for IPv6 or 0001 for IPv4")
        end

        addresses = node[2]
        tagisa(addresses, ASN.SEQUENCE)
        addresses.nicename = "addresses"
        if length(addresses.children) == 0
            err!(addresses, "there should be at least one ROAIPAddress here")
        end
        if tpi.afi == 1 # IPv4
            node[1].nicename = "addressFamily: IPv4"
        else
            node[1].nicename = "addressFamily: IPv6"
        end
        for roa_ipaddress in addresses.children
            check_ASN1_ROAIPAddress(o, roa_ipaddress, tpi)
        end
end
@check "ipAddrBlocks" begin
    tagisa(node, ASN.SEQUENCE)

    if length(node.children) == 0
        err!(node, "there should be at least one ROAIPAddressFamily here")
    end
    for roa_afi in node.children
        check_ASN1_ROAIPAddressFamily(o, roa_afi, tpi)
    end
end

@check "routeOriginAttestation" begin
    tagisa(node, ASN.SEQUENCE)
    checkchildren(node, 2:3)
    # the 'version' is optional, defaults to 0
    offset = 0
    if length(node.children) == 6
		check_ASN1_version(o, node[1], tpi)
        offset += 1
	end
    check_ASN1_asID(o, node[offset+1], tpi)
    check_ASN1_ipAddrBlocks(o, node[offset+2], tpi)
end

function check_ASN1(o::RPKIObject{ROA}, tpi::TmpParseInfo) :: RPKIObject{ROA}
    cmsobject = o.tree
    # CMS, RFC5652:
    #       ContentInfo ::= SEQUENCE {
    #           contentType ContentType,
    #           content [0] EXPLICIT ANY DEFINED BY contentType }
    
    tagisa(cmsobject, ASN.SEQUENCE)
    checkchildren(cmsobject, 2)

    CMS.check_ASN1_contentType(o, cmsobject[1], tpi)
    CMS.check_ASN1_content(o, cmsobject[2], tpi)

    check_ASN1_routeOriginAttestation(o, tpi.eContent, tpi)

    o
end

function check_cert(o::RPKIObject{ROA}, tpi::TmpParseInfo)
    # hash tpi.eeCert
    @assert !isnothing(tpi.eeCert)
    tbs_raw = read(o.filename, tpi.eeCert.tag.offset_in_file + tpi.eeCert.tag.len + 4 - 1)[tpi.eeCert.tag.offset_in_file+0:end]
    my_hash = bytes2hex(sha256(tbs_raw))

    # decrypt tpi.eeSig with tpi.ca_rsaModulus and tpi.ca_rsaExponent
    v = powermod(to_bigint(tpi.eeSig.tag.value[2:end]), tpi.ca_rsaExponent[end], tpi.ca_rsaModulus[end])
    v.size = 4
    v_str = string(v, base=16, pad=64)
    
    # compare hashes
    if v_str != my_hash
        @error "invalid signature for" o.filename
    end

    # compare subject with SKI
    # TODO
end
