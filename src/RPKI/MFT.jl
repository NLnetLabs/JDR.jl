module Mft
using ...ASN1
using ...RPKI
using ...RPKICommon
using SHA
using ...PKIX.CMS
using ..JDR.Common

using Dates

import ...PKIX.@check


export check_ASN1, check_cert

function Base.show(io::IO, mft::MFT)
    print(io, "  num of files: ", length(mft.files), '\n')
    if !isnothing(mft.missing_files)
        printstyled(io, "  missing files: \n")
        for m in mft.missing_files
            print(io, "    ", m, '\n')
        end
    end
    print(io, "  thisUpdate: ", mft.this_update, '\n')
    print(io, "  nextUpdate: ", mft.next_update, '\n')
end

function add_missing_file(m::MFT, filename::String)
    if isnothing(m.missing_files)
        m.missing_files = [filename]
    else
        push!(m.missing_files, filename)
    end
end

function gentime_to_ts(raw::Vector{UInt8})
    DateTime(String(copy(raw)), dateformat"yyyymmddHHMMSSZ")
end

import Base.length
length(::Nothing) = 0 #used in childcount from validation_common.jl

@check "version" begin
    tagis_contextspecific(node, 0x00)
    # EXPLICIT tagging, so the version node be in a child
    childcount(node, 1)
    check_tag(node[1], ASN1.INTEGER)
    if value(node[1].tag) == 0
        #info!(node[1], "version explicitly set to 0 while that is the default")
    end
end

@check "manifestNumber" begin
    check_tag(node, ASN1.INTEGER)
end

@check "thisUpdate" begin
    check_tag(node, ASN1.GENTIME)
    try
        o.object.this_update = (@__MODULE__).gentime_to_ts(node.tag.value)
    catch e
        if e isa ArgumentError
            remark_ASN1Error!(o, "Could not parase GENTIME in thisUpdate field")
        else
            @error e
        end
    end
end
@check "nextUpdate" begin
    check_tag(node, ASN1.GENTIME)
    try
        o.object.next_update = (@__MODULE__).gentime_to_ts(node.tag.value)
    catch e
        if e isa ArgumentError
            remark_ASN1Error!(o, "Could not parase GENTIME in nextUpdate field")
        else
            @error e
        end
    end
end

@check "fileHashAlg" begin
    check_OID(node, @oid "2.16.840.1.101.3.4.2.1")
end

@check "fileList" begin
    check_tag(node, ASN1.SEQUENCE)
    for file_and_hash in node.children
        check_tag(file_and_hash, ASN1.SEQUENCE)
        check_tag(file_and_hash[1], ASN1.IA5STRING)
        check_tag(file_and_hash[2], ASN1.BITSTRING)

        filename = ASN1.value(file_and_hash[1].tag)
        push!(o.object.files, filename)

        full_fn = tpi.cwd*'/'*filename
        if isfile(full_fn) # TODO redundancy with process_mft in RPKI.jl
            open(full_fn) do fh
                local_hash = sha256(fh)
                if file_and_hash[2].tag.len != 33
                    @warn "illegal file hash length in $(o.filename) for filename $(filename)"
                    remark_ASN1Error!(file_and_hash[2], "Expecting length of 33")
                elseif local_hash != file_and_hash[2].tag.value[end-31:end]
                    @warn "invalid hash for", full_fn
                    remark_manifestIssue!(o, "Invalid hash for $(filename)")
                end
            end
        end
    end
end

@check "manifest" begin
    # Manifest ::= SEQUENCE {
    #  version     [0] INTEGER DEFAULT 0,
    #  manifestNumber  INTEGER (0..MAX),
    #  thisUpdate      GeneralizedTime,
    #  nextUpdate      GeneralizedTime,
    #  fileHashAlg     OBJECT IDENTIFIER,
    #  fileList        SEQUENCE SIZE (0..MAX) OF FileAndHash
    #  }
    check_tag(node, ASN1.SEQUENCE)
    childcount(node, 5:6)
    # the 'version' is optional, defaults to 0
    offset = 0
    if length(node.children) == 6
        (@__MODULE__).check_ASN1_version(o, node[1], tpi)
        offset += 1
	end
    (@__MODULE__).check_ASN1_manifestNumber(o, node[offset+1], tpi)
    (@__MODULE__).check_ASN1_thisUpdate(o, node[offset+2], tpi)
    (@__MODULE__).check_ASN1_nextUpdate(o, node[offset+3], tpi)
    (@__MODULE__).check_ASN1_fileHashAlg(o, node[offset+4], tpi)
    (@__MODULE__).check_ASN1_fileList(o, node[offset+5], tpi)
end

import ..RPKI:check_ASN1
function RPKI.check_ASN1(o::RPKIObject{MFT}, tpi::TmpParseInfo) :: RPKIObject{MFT}
    #@debug "check_ASN1 in MFT called"
    cmsobject = o.tree
    # CMS, RFC5652:
    #       ContentInfo ::= SEQUENCE {
    #           contentType ContentType,
    #           content [0] EXPLICIT ANY DEFINED BY contentType }
    
    check_tag(cmsobject, ASN1.SEQUENCE)
    childcount(cmsobject, 2)

    CMS.check_ASN1_contentType(o, cmsobject[1], tpi)
    CMS.check_ASN1_content(o, cmsobject[2], tpi)

    check_ASN1_manifest(o, tpi.eContent, tpi)

    o
end

import .RPKI:check_cert
function RPKI.check_cert(o::RPKIObject{MFT}, tpi::TmpParseInfo)
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

end
