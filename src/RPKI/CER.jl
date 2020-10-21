module Cer

using ...JDR.Common
using ...RPKI
using ...ASN1
using ...PKIX.X509
using SHA
using IntervalTrees
using IPNets

export check_ASN1, check_cert, check_resources

import .RPKI:check_ASN1
function check_ASN1(o::RPKIObject{CER}, tpi::TmpParseInfo=TmpParseInfo()) :: RPKIObject{CER}
    # The certificate should consist of three parts: (RFC5280)
	# Certificate  ::=  SEQUENCE  {
	#      tbsCertificate       TBSCertificate,
	#      signatureAlgorithm   AlgorithmIdentifier,
	#      signature            BIT STRING  }
    

    childcount(o.tree, 3) # this one marks the SEQUENCE as checked!
    tbsCertificate = o.tree.children[1]
    X509.check_ASN1_tbsCertificate(o, tbsCertificate, tpi)
    
    o
end

function check(o::RPKIObject{CER}, tpi::TmpParseInfo=TmpParseInfo())
    @warn "DEPRECATED CER.check(), use CER.check_ASN1()" maxlog=3
    check_ASN1(o, tpi)
end

import .RPKI:check_cert
function check_cert(o::RPKIObject{CER}, tpi::TmpParseInfo) :: RPKI.RPKIObject{CER}
    if !o.object.selfsigned && tpi.certStack[end-1].subject != o.object.issuer
        @error "subject != issuer for child cert $(o.filename)"
        err!(o, "subject != issuer for child cert")
    end
    sig = o.tree.children[3]
    signature = to_bigint(sig.tag.value[2:end])
    @assert !isnothing(o.object.selfsigned)
    v = if o.object.selfsigned
        powermod(signature, tpi.certStack[end].rsa_exp, tpi.certStack[end].rsa_modulus)
    else
        powermod(signature, tpi.certStack[end-1].rsa_exp, tpi.certStack[end-1].rsa_modulus)
    end
    v.size = 4
    v_str = string(v, base=16, pad=64)

    tbs_raw = read(o.filename, o.tree[2].tag.offset_in_file-1)[o.tree[1].tag.offset_in_file:end]
    my_hash = bytes2hex(sha256(tbs_raw))

    # this only described whether the signature is valid or not! no resource
    # checks done at this point
    tpi.certValid = v_str == my_hash
    o
end

# TODO: add a resourcesValid flag somewhere
# and perhaps, on the RPKINode level, create a pointer to the covering CER
function check_resources(o::RPKIObject{CER}, tpi::TmpParseInfo)
    if !o.object.selfsigned
        if isempty(o.object.ASNs) && !o.object.inherit_ASNs
            #@error "empty ASNs and no inheritance? $(o.filename)" maxlog=3
            warn!(o, "empty ASNs but no inherit")
        end
        if !covered(o.object.ASNs , tpi.certStack[end-1].ASNs)
            # not covered, so check for inherited ASNs in parent certificates
            @assert tpi.certStack[end-1].inherit_ASNs
            for parent in reverse(tpi.certStack[1:end-2])
                if !parent.inherit_ASNs
                    @assert covered(o.object.ASNs, parent.ASNs)
                    #@debug "$(o.filename) covered by $(parent.issuer)"
                    return
                end
            end

            @error "illegal ASNs in $(o.filename)"
            @debug o.object.ASNs
            @debug tpi.certStack[end-1].ASNs
            throw("illegal resources")
        end
    end

    # now for the prefixes
    # TODO merge somehow with the ASN loop above?
    #=
    #temporary, see if things work before checking and changing this part..
    if !o.object.selfsigned
        certStackOffset_v6 = certStackOffset_v4 = 1
        if isempty(o.object.prefixes_v6) 
            if isnothing(o.object.inherit_v6_prefixes)
                #@warn "v6 prefixes empty, but inherit bool is not set.."
                #@error "empty v6 prefixes undefined inheritance? $(o.filename)"
            elseif !(o.object.inherit_v6_prefixes)
                @warn "v6 prefixes empty, inherit bool set to false.."
                @error "empty v6 prefixes and no inheritance? $(o.filename)"
                ResourceIssue!(o, "No IPv6 prefixes and no inherit flag set")
            end
        else
            while tpi.certStack[end-certStackOffset_v6].inherit_v6_prefixes
                @assert length(tpi.certStack[end-certStackOffset_v6].prefixes_v6) == 0
                #@debug "parent says inherit_prefixes, increasing offset to $(certStackOffset+1)"
                certStackOffset_v6 += 1
            end
        end
        if isempty(o.object.prefixes_v4) 
            if isnothing(o.object.inherit_v4_prefixes)
                #@warn "v4 prefixes empty, but inherit bool is not set.."
                #@error "empty v4 prefixes undefined inheritance? $(o.filename)"
            elseif !(o.object.inherit_v4_prefixes)
                @warn "v4 prefixes empty, inherit bool set to false.."
                @error "empty v4 prefixes and no inheritance? $(o.filename)"
                ResourceIssue!(o, "No IPv4 prefixes and no inherit flag set")
            end
        else
            while tpi.certStack[end-certStackOffset_v4].inherit_v4_prefixes
                @assert length(tpi.certStack[end-certStackOffset_v4].prefixes_v4) == 0
                #@debug "parent says inherit_prefixes, increasing offset to $(certStackOffset+1)"
                certStackOffset_v4 += 1
            end
        end
        
        checking_on_0_v6 = checking_on_0_v4 = false
        if tpi.certStack[end - certStackOffset_v6].prefixes_v6 == IPPrefixesOrRanges([IPPrefix("::/0")])
            #@warn "checking resources for $(o.filename) against /0, offset $(certStackOffset)/$(length(tpi.certStack))"
            checking_on_0_v6 = true
        #elseif isempty(tpi.certStack[end - certStackOffset].prefixes)
        #    @warn "prefixes in parent cert empty"
        else
            #@debug tpi.certStack[end - certStackOffset].prefixes
            #throw("debug")
        end
        if tpi.certStack[end - certStackOffset_v4].prefixes_v4 == IPPrefixesOrRanges([IPPrefix("0/0")])
            checking_on_0_v4 = true
        end

        for p in o.object.prefixes_v6
            interval = if p isa IPPrefix
                if p.netmask == 0
                    @assert p isa IPv6Net
                    Interval{Integer}(UInt128(1) << 125, typemax(UInt128))
                else
                    Interval{Integer}(minimum(p), maximum(p))
                end
            elseif p isa IPRange
                Interval{Integer}(p.first.netaddr, p.last.netaddr)
            else
                throw("illegal prefix type")
            end

            matches = collect(intersect(tpi.certStack[end-certStackOffset_v6].prefixes_v6_intervaltree, interval))
            if length(matches) > 1
                if length(matches) == 2 && checking_on_0_v6
                else
                    @warn "$(p) matched by $(length(matches))"
                    @debug matches
                    @debug tpi.certStack[end-certStackOffset_v6].prefixes_v6
                end
            elseif length(matches) == 1
                # now check the intersection is actually within the boundaries
                # of the parent
                if !(matches[1].first <= first_ip(p) <= last_ip(p) <= matches[1].last)
                    @error "intersection but not properly covering!"
                    @debug p
                    @debug matches[1]
                end
                #@info "$(p) is covered by $(matches[1])"
            else
                @error "overclaim! $(p) not in parent's prefix_intervaltree"
            end
        end
        for p in o.object.prefixes_v4
            interval = if p isa IPPrefix
                if p.netmask == 0
                    @assert p isa IPv4Net
                    Interval{Integer}(0, typemax(UInt32))
                else
                    Interval{Integer}(minimum(p), maximum(p))
                end
            elseif p isa IPRange
                Interval{Integer}(p.first.netaddr, p.last.netaddr)
            else
                throw("illegal prefix type")
            end

            matches = collect(intersect(tpi.certStack[end-certStackOffset_v4].prefixes_v4_intervaltree, interval))
            if length(matches) > 1
                if length(matches) == 2 && checking_on_0_v4
                else
                    @warn "$(p) matched by $(length(matches))"
                    @debug matches
                    @debug tpi.certStack[end-certStackOffset_v4].prefixes_4
                end
            elseif length(matches) == 1
                # now check the intersection is actually within the boundaries
                # of the parent
                if !(matches[1].first <= first_ip(p) <= last_ip(p) <= matches[1].last)
                    @error "intersection but not properly covering!"
                    @debug p
                    @debug matches[1]
                end
                #@info "$(p) is covered by $(matches[1])"
            else
                @error "overclaim! $(p) not in parent's prefix_intervaltree"
            end
        end
    end
    =#

end


end # module
