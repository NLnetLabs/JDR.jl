module Mft
using ...ASN
using ...RPKI
using ...RPKICommon
using SHA
using ...PKIX.CMS

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
length(::Nothing) = 0 #used in checkchildren from validation_common.jl

@check "version" begin
    tagis_contextspecific(node, 0x00)
    # EXPLICIT tagging, so the version node be in a child
    checkchildren(node, 1)
    tagisa(node[1], ASN.INTEGER)
    if value(node[1].tag) == 0
        info!(node[1], "version explicitly set to 0 while that is the default")
    end
end

@check "manifestNumber" begin
    tagisa(node, ASN.INTEGER)
end

@check "thisUpdate" begin
    tagisa(node, ASN.GENTIME)
    try
        o.object.this_update = (@__MODULE__).gentime_to_ts(node.tag.value)
    catch e
        if e isa ArgumentError
            err!(o, "Could not parase GENTIME in thisUpdate field")
        else
            @error e
        end
    end
end
@check "nextUpdate" begin
    tagisa(node, ASN.GENTIME)
    try
        o.object.next_update = (@__MODULE__).gentime_to_ts(node.tag.value)
    catch e
        if e isa ArgumentError
            err!(o, "Could not parase GENTIME in nextUpdate field")
        else
            @error e
        end
    end
end

@check "fileHashAlg" begin
    tag_OID(node, @oid "2.16.840.1.101.3.4.2.1")
end

@check "fileList" begin
    tagisa(node, ASN.SEQUENCE)
    #@debug "manifest files: $(length(node.children))"
    for file_and_hash in node.children
        tagisa(file_and_hash, ASN.SEQUENCE)
        tagisa(file_and_hash[1], ASN.IA5STRING)
        tagisa(file_and_hash[2], ASN.BITSTRING)
        push!(o.object.files, value(file_and_hash[1].tag))
    end
    #@debug "pushed files: $(length(o.object.files))"
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
    tagisa(node, ASN.SEQUENCE)
    checkchildren(node, 5:6)
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

import .RPKI:check_ASN1
function check_ASN1(o::RPKIObject{MFT}, tpi::TmpParseInfo) :: RPKIObject{MFT}
    cmsobject = o.tree
    # CMS, RFC5652:
    #       ContentInfo ::= SEQUENCE {
    #           contentType ContentType,
    #           content [0] EXPLICIT ANY DEFINED BY contentType }
    
    tagisa(cmsobject, ASN.SEQUENCE)
    checkchildren(cmsobject, 2)

    CMS.check_ASN1_contentType(o, cmsobject[1], tpi)
    CMS.check_ASN1_content(o, cmsobject[2], tpi)

    check_ASN1_manifest(o, tpi.eContent, tpi)

    o
end

import .RPKI:check_cert
function check_cert(o::RPKIObject{MFT}, tpi::TmpParseInfo)
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

end
