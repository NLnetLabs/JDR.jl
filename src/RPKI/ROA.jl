module Roa
using SHA

using ...Common
using ...PKIX.CMS
using ...RPKI
using ...RPKICommon
using ...ASN1

using IPNets
using Sockets
using IntervalTrees

import ...PKIX.@check

#export ROA, check_ASN1
export check_ASN1


function Base.show(io::IO, roa::ROA)
    println(io, "ASID: ", roa.asid)
    #print(io, "  VRPs:\n")
    #for vrp in roa.vrps
    #    print(io, "    ", vrp.prefix, "-", vrp.maxlength, "\n")
    #end
    println(io, "VRPs:")
    for vrp in roa.vrp_tree.resources_v6
        println(io, "    ", IPRange(vrp.first, vrp.last), "-", vrp.value)
    end
    for vrp in roa.vrp_tree.resources_v4
        println(io, "    ", IPRange(vrp.first, vrp.last), "-", vrp.value)
    end
end

#= # not used?
function rawv4_to_roa(o::RPKIObject{ROA}, roa_ipaddress::Node) :: RPKIObject{ROA}
    tagisa(roa_ipaddress, ASN1.SEQUENCE)
    tagisa(roa_ipaddress[1], ASN1.BITSTRING)

    prefix = bitstring_to_ipv4net(roa_ipaddress[1].tag.value)
    maxlength = prefix.netmask #FIXME @code_warntype ?

    # optional maxLength:
    if length(roa_ipaddress.children) == 2
        tagisa(roa_ipaddress[2], ASN1.INTEGER)
        @assert roa_ipaddress[2].tag.len == 1
        #if ASN1.value(roa_ipaddress[2].tag) == maxlength
        if roa_ipaddress[2].tag.value[1] == maxlength
            #info!(roa_ipaddress[2], "redundant maxLength")
        else
            maxlength = roa_ipaddress[2].tag.value[1]
        end
    end
    push!(o.object.vrps, VRP(prefix, maxlength))
    o
end
function rawv6_to_roa(o::RPKIObject{ROA}, roa_ipaddress::Node) :: RPKIObject{ROA}
    tagisa(roa_ipaddress, ASN1.SEQUENCE)
    tagisa(roa_ipaddress[1], ASN1.BITSTRING)

    prefix = bitstring_to_ipv6net(roa_ipaddress[1].tag.value)
    maxlength = prefix.netmask

    # optional maxLength:
    if length(roa_ipaddress.children) == 2
        tagisa(roa_ipaddress[2], ASN1.INTEGER)
        explicit_len = if roa_ipaddress[2].tag.len == 1
            #@debug roa_ipaddress[2].tag.value
            roa_ipaddress[2].tag.value[1]
        elseif roa_ipaddress[2].tag.len == 2
            reinterpret(Int16, [roa_ipaddress[2].tag.value[2], roa_ipaddress[2].tag.value[1]])[1]
        else
            value(roa_ipaddress[2].tag)
        end
        if explicit_len == maxlength
            #info!(roa_ipaddress[2], "redundant maxLength")
        else
            maxlength = explicit_len
        end
    end

    push!(o.object.vrps, VRP(prefix, maxlength))
    o
end
=#

@check "version" begin
    tagis_contextspecific(node, 0x00)
    # EXPLICIT tagging, so the version node be in a child
    childcount(node, 1)
    tagisa(node[1], ASN1.INTEGER)
    if value(node[1].tag) == 0
        #info!(node[1], "version explicitly set to 0 while that is the default")
    end
end

@check "asID" begin
    tagisa(node, ASN1.INTEGER)
    o.object.asid = ASN1.value(node.tag)
end
@check "ROAIPAddress" begin
    tagisa(node, ASN1.SEQUENCE)
    tagisa(node[1], ASN1.BITSTRING)
    node[1].nicename = "address"

    prefix = if tpi.afi == 1
        #bitstring_to_ipv4net(node[1].tag.value)
        bitstring_to_v4range(node[1].tag.value)
    elseif tpi.afi == 2
        #bitstring_to_ipv6net(node[1].tag.value)
        bitstring_to_v6range(node[1].tag.value)
    else
        throw("illegal AFI in check_ASN1_ROAIPAddress")
    end

    #maxlength = prefix.netmask #FIXME @code_warntype ?
    maxlength = UInt8(prefixlen(prefix))

    # optional maxLength:
    if length(node.children) == 2
        tagisa(node[2], ASN1.INTEGER)
        node[2].nicename = "maxLength"
        #@assert node[2].tag.len == 1
        if node[2].tag.value[1] == maxlength
            #remark_ASN1Issue!(node[2], "redundant maxLength")
        else
            maxlength = node[2].tag.value[1]
        end
    end
    push!(o.object.vrps, (@__MODULE__).VRP(prefix, maxlength))

    if tpi.afi == 1
        push!(o.object.vrp_tree.resources_v4, IntervalValue(prefix.first, prefix.last, maxlength))
    elseif tpi.afi == 2
        push!(o.object.vrp_tree.resources_v6, IntervalValue(prefix.first, prefix.last, maxlength))
    end

end
@check "ROAIPAddressFamily" begin
        tagisa(node, ASN1.SEQUENCE)
        # addressFamily
        tagisa(node[1], ASN1.OCTETSTRING)

        tpi.afi = reinterpret(UInt16, reverse(node[1].tag.value))[1]
        if ! (tpi.afi in [1,2])
            @error "invalid AFI in ROA"
            remark_ASN1Error!(node[1], "addressFamily MUST be either 0002 for IPv6 or 0001 for IPv4")
        end

        addresses = node[2]
        tagisa(addresses, ASN1.SEQUENCE)
        addresses.nicename = "addresses"
        if length(addresses.children) == 0
            remark_ASN1Error!(addresses, "there should be at least one ROAIPAddress here")
        end
        if tpi.afi == 1 # IPv4
            node[1].nicename = "addressFamily: IPv4"
        else
            node[1].nicename = "addressFamily: IPv6"
        end
        for roa_ipaddress in addresses.children
            (@__MODULE__).check_ASN1_ROAIPAddress(o, roa_ipaddress, tpi)
        end
end
@check "ipAddrBlocks" begin
    tagisa(node, ASN1.SEQUENCE)

    if length(node.children) == 0
        remark_ASN1Error!(node, "there should be at least one ROAIPAddressFamily here")
    end
    for roa_afi in node.children
        (@__MODULE__).check_ASN1_ROAIPAddressFamily(o, roa_afi, tpi)
    end
end

@check "routeOriginAttestation" begin
    tagisa(node, ASN1.SEQUENCE)
    childcount(node, 2:3)
    # the 'version' is optional, defaults to 0
    offset = 0
    if length(node.children) == 6
		check_ASN1_version(o, node[1], tpi)
        offset += 1
	end
    (@__MODULE__).check_ASN1_asID(o, node[offset+1], tpi)
    (@__MODULE__).check_ASN1_ipAddrBlocks(o, node[offset+2], tpi)
end

import .RPKI:check_ASN1
function check_ASN1(o::RPKIObject{ROA}, tpi::TmpParseInfo) :: RPKIObject{ROA}
    cmsobject = o.tree
    # CMS, RFC5652:
    #       ContentInfo ::= SEQUENCE {
    #           contentType ContentType,
    #           content [0] EXPLICIT ANY DEFINED BY contentType }
    
    tagisa(cmsobject, ASN1.SEQUENCE)
    childcount(cmsobject, 2)

    CMS.check_ASN1_contentType(o, cmsobject[1], tpi)
    CMS.check_ASN1_content(o, cmsobject[2], tpi)

    check_ASN1_routeOriginAttestation(o, tpi.eContent, tpi)

    o
end

import .RPKI:check_cert
function check_cert(o::RPKIObject{ROA}, tpi::TmpParseInfo)
    # hash tpi.eeCert
    @assert !isnothing(tpi.eeCert)
    tbs_raw = read(o.filename, tpi.eeCert.tag.offset_in_file + tpi.eeCert.tag.len + 4 - 1)[tpi.eeCert.tag.offset_in_file+0:end]
    my_hash = bytes2hex(sha256(tbs_raw))

    # decrypt tpi.eeSig 
    v = powermod(to_bigint(tpi.eeSig.tag.value[2:end]), tpi.certStack[end].rsa_exp,tpi.certStack[end].rsa_modulus)
    v.size = 4
    v_str = string(v, base=16, pad=64)
    
    # compare hashes
    if v_str == my_hash
        o.sig_valid = true
    else
        @error "invalid signature for" o.filename
        remark_validityIssue!(o, "invalid signature")
        o.sig_valid = false
    end

    # compare subject with SKI
    # TODO
end

import .RPKI.add_resource!
function add_resource!(roa::ROA, minaddr::IPv6, maxaddr::IPv6)
	push!(roa.resources_v6, IntervalValue(minaddr, maxaddr, VRP[]))
end
function add_resource!(roa::ROA, minaddr::IPv4, maxaddr::IPv4)
	push!(roa.resources_v4, IntervalValue(minaddr, maxaddr, VRP[]))
end
add_resource!(roa::ROA, ipr::IPRange{IPv6}) = push!(roa.resources_v6, IntervalValue(ipr, VRP[]))
add_resource!(roa::ROA, ipr::IPRange{IPv4}) = push!(roa.resources_v4, IntervalValue(ipr, VRP[]))

import .RPKI:check_resources
function check_resources(o::RPKIObject{ROA}, tpi::TmpParseInfo)
    # TODO: check out intersect(t1::IntervalTree, t2::IntervalTree) and find any
    # underclaims?
    o.object.resources_valid = true


    # first, check the resources on the EE are properly covered by the resources
    # in the parent CER
    # TODO: check: can the parent cer have inherit set instead of listing actual
    # resources?

    #v6:
    if !isempty(o.object.resources_v6)
        overlap_v6 = collect(intersect(tpi.certStack[end].resources_v6, o.object.resources_v6))
        if length(overlap_v6) == 0
            @warn "IPv6 resource on EE in $(o.filename) not covered by parent certificate $(tpi.certStack[end].subject)"
            remark_resourceIssue!(o, "IPv6 resource on EE not covered by parent certificate")
            o.object.resources_valid = false
        else
            for (p, ee) in overlap_v6
                if !(p.first <= ee.first <= ee.last <= p.last)
                    @warn "IPv6 resource on EE in $(o.filename) not properly covered by parent certificate"
                    remark_resourceIssue!(o, "Illegal IP resource $(ee)")
                    o.object.resources_valid = false
                end
            end
        end
    end
    #v4:
    if !isempty(o.object.resources_v4)
        overlap_v4 = collect(intersect(tpi.certStack[end].resources_v4, o.object.resources_v4))
        if length(overlap_v4) == 0
            @warn "IPv4 resource on EE in $(o.filename) not covered by parent certificate $(tpi.certStack[end].subject)"
            remark_resourceIssue!(o, "IPv4 resource on EE not covered by parent certificate")
            o.object.resources_valid = false
        else
            for (p, ee) in overlap_v4
                if !(p.first <= ee.first <= ee.last <= p.last)
                    @warn "IPv4 resource on EE in $(o.filename) not properly covered by parent certificate"
                    remark_resourceIssue!(o, "Illegal IP resource $(ee)")
                    o.object.resources_valid = false
                end
            end
        end
    end


    # --

    # now that we know the validity of the resources on the EE, verify that the
    # VRPs are covered by the resources on the EE


    # attempt with new vrp_tree

    # IPv6:
    Common.check_coverage(o.object.resources_v6, o.object.vrp_tree.resources_v6) do invalid
        @warn "illegal IPv6 VRP $(IPRange(invalid.first, invalid.last)) not covered by EE on $(o.filename)"
        remark_resourceIssue!(o, "Illegal IPv6 VRP $(IPRange(invalid.first, invalid.last))")
        o.object.resources_valid = false
    end

    # IPv4:
    Common.check_coverage(o.object.resources_v4, o.object.vrp_tree.resources_v4) do invalid
        @warn "illegal IPv4 VRP $(IPRange(invalid.first, invalid.last)) not covered by EE on $(o.filename)"
        remark_resourceIssue!(o, "Illegal IPv4 VRP $(IPRange(invalid.first, invalid.last))")
        o.object.resources_valid = false
    end

    #= # TMP while refactoring into IntervalTree
    for v in o.object.vrps
        #@debug "checking $(v)"
        #interval = Interval{IPAddr}(minimum(v.prefix), maximum(v.prefix))
        matches = if v.prefix isa IPv6Net
            collect(intersect(o.object.resources_v6, Interval{IPv6}(minimum(v.prefix), maximum(v.prefix))))
        elseif v.prefix isa IPv4Net
            #collect(intersect(o.object.resources_v4, interval))
            collect(intersect(o.object.resources_v4, Interval{IPv4}(minimum(v.prefix), maximum(v.prefix))))
        else
            throw("illegal AFI in VRP")
        end
        if length(matches) > 1
            @warn "ROA resource check: multiple matches for $(v)"
        elseif length(matches) == 0
            @warn "no match, illegal VRP $(v)"
            remark_resourceIssue!(o, "VRP not covered by resources in EE cert")
            o.object.resources_valid = false
        else
            if !(matches[1].first <= v.prefix[1] <= v.prefix[end] <= matches[1].last)
                @warn "VRP not properly covered by resources in EE cert"
                remark_resourceIssue!(o, "VRP not properly covered by resources in EE cert")
                o.object.resources_valid = false
            end
        end
    end
    =#
end

end # module
