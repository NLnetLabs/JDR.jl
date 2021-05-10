module Roa

using JDR.ASN1: ASN1, check_contextspecific, childcount, check_tag, value, bitstring_to_v6range
using JDR.ASN1: bitstring_to_v4range, to_bigint
using JDR.Common: IPRange, check_coverage, prefixlen, remark_ASN1Error!, remark_resourceIssue!
using JDR.Common: remark_validityIssue!
using JDR.PKIX.CMS: check_ASN1_contentType, check_ASN1_content # from macros
using JDR.RPKICommon: ROA, RPKIObject, RPKIFile, TmpParseInfo

using IntervalTrees: Interval, IntervalValue
using SHA: sha256
using Sockets: IPv6, IPv4

import JDR.RPKI # to extend check_ASN1, check_cert, add_resource!, check_resources
include("../ASN1/macro_check.jl")


function Base.show(io::IO, roa::ROA)
    println(io, "ASID: ", roa.asid)
    println(io, "VRPs:")
    for vrp in roa.vrp_tree.resources_v6
        println(io, "    ", IPRange(vrp.first, vrp.last), "-", vrp.value)
    end
    for vrp in roa.vrp_tree.resources_v4
        println(io, "    ", IPRange(vrp.first, vrp.last), "-", vrp.value)
    end
end

@check "version" begin
    check_contextspecific(node, 0x00)
    # EXPLICIT tagging, so the version node be in a child
    childcount(node, 1)
    check_tag(node[1], ASN1.INTEGER)
    if value(node[1].tag) == 0
        #info!(node[1], "version explicitly set to 0 while that is the default")
    end
end

@check "asID" begin
    check_tag(node, ASN1.INTEGER)
    o.object.asid = ASN1.value(node.tag)
end
@check "ROAIPAddress" begin
    check_tag(node, ASN1.SEQUENCE)
    check_tag(node[1], ASN1.BITSTRING)
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

    maxlength = UInt8(prefixlen(prefix))

    # optional maxLength:
    if length(node.children) == 2
        check_tag(node[2], ASN1.INTEGER)
        node[2].nicename = "maxLength"
        #@assert node[2].tag.len == 1
        if node[2].tag.value[1] == maxlength
            #remark_ASN1Issue!(node[2], "redundant maxLength")
        else
            maxlength = node[2].tag.value[1]
        end
    end
    #push!(o.object.vrps, (@__MODULE__).VRP(prefix, maxlength))

    if tpi.afi == 1
        push!(o.object.vrp_tree.resources_v4, IntervalValue(prefix.first, prefix.last, maxlength))
    elseif tpi.afi == 2
        push!(o.object.vrp_tree.resources_v6, IntervalValue(prefix.first, prefix.last, maxlength))
    end

end
@check "ROAIPAddressFamily" begin
        check_tag(node, ASN1.SEQUENCE)
        # addressFamily
        check_tag(node[1], ASN1.OCTETSTRING)

        tpi.afi = reinterpret(UInt16, reverse(node[1].tag.value))[1]
        if ! (tpi.afi in [1,2])
            @error "invalid AFI in ROA"
            remark_ASN1Error!(node[1], "addressFamily MUST be either 0002 for IPv6 or 0001 for IPv4")
        end

        addresses = node[2]
        check_tag(addresses, ASN1.SEQUENCE)
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
    check_tag(node, ASN1.SEQUENCE)

    if length(node.children) == 0
        remark_ASN1Error!(node, "there should be at least one ROAIPAddressFamily here")
    end
    for roa_afi in node.children
        (@__MODULE__).check_ASN1_ROAIPAddressFamily(o, roa_afi, tpi)
    end
end

@check "routeOriginAttestation" begin
    check_tag(node, ASN1.SEQUENCE)
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

function RPKI.check_ASN1(o::RPKIObject{ROA}, tpi::TmpParseInfo) :: RPKIObject{ROA}
    cmsobject = o.tree
    # CMS, RFC5652:
    #       ContentInfo ::= SEQUENCE {
    #           contentType ContentType,
    #           content [0] EXPLICIT ANY DEFINED BY contentType }
    
    check_tag(cmsobject, ASN1.SEQUENCE)
    childcount(cmsobject, 2)

    # from CMS.jl:
    check_ASN1_contentType(o, cmsobject[1], tpi)
    check_ASN1_content(o, cmsobject[2], tpi)

    check_ASN1_routeOriginAttestation(o, tpi.eContent, tpi)

    o
end

function RPKI.check_cert(o::RPKIObject{ROA}, tpi::TmpParseInfo)
    # hash tpi.eeCert
    @assert !isnothing(tpi.eeCert)
    tbs_raw = @view o.tree.buf.data[tpi.eeCert.tag.offset_in_file:tpi.eeCert.tag.offset_in_file + tpi.eeCert.tag.len + 4 - 1]
    my_hash = bytes2hex(sha256(tbs_raw))

    # decrypt tpi.eeSig 
    v = powermod(to_bigint(@view tpi.eeSig.tag.value[2:end]), tpi.certStack[end].rsa_exp,tpi.certStack[end].rsa_modulus)
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

#import .RPKI.add_resource!
#function RPKI.add_resource!(roa::ROA, minaddr::IPv6, maxaddr::IPv6)
#	push!(roa.resources_v6, IntervalValue(minaddr, maxaddr, VRP[]))
#end
#function RPKI.add_resource!(roa::ROA, minaddr::IPv4, maxaddr::IPv4)
#	push!(roa.resources_v4, IntervalValue(minaddr, maxaddr, VRP[]))
#end
RPKI.add_resource!(roa::ROA, ipr::IPRange{IPv6}) = push!(roa.resources_v6, Interval(ipr))
RPKI.add_resource!(roa::ROA, ipr::IPRange{IPv4}) = push!(roa.resources_v4, Interval(ipr))

function RPKI.check_resources(o::RPKIObject{ROA}, tpi::TmpParseInfo)
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
    check_coverage(o.object.resources_v6, o.object.vrp_tree.resources_v6) do invalid
        @warn "illegal IPv6 VRP $(IPRange(invalid.first, invalid.last)) not covered by EE on $(o.filename)"
        remark_resourceIssue!(o, "Illegal IPv6 VRP $(IPRange(invalid.first, invalid.last))")
        o.object.resources_valid = false
    end

    # IPv4:
    check_coverage(o.object.resources_v4, o.object.vrp_tree.resources_v4) do invalid
        @warn "illegal IPv4 VRP $(IPRange(invalid.first, invalid.last)) not covered by EE on $(o.filename)"
        remark_resourceIssue!(o, "Illegal IPv4 VRP $(IPRange(invalid.first, invalid.last))")
        o.object.resources_valid = false
    end
end

end # module
