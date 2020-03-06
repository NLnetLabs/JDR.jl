module DER
using ..ASN
# Possible/common mistakes or violations:
# - a primitive BITSTRING actually containing other tags (thus being constructed)
# - encapsulating OCTETSTRINGS?
# - no terminating \x0000 in an Indefinite form BITSTRING? in the ripe ta cer this seems to be the
# case. Perhaps they rely on the Length of the root SEQUENCE?

#struct Buf
#    buffer::Array{UInt8, 1}
#    index::UInt64
#    Buf(b) = new(b, 1)
#end
#
#
# TODO
# - try OwnTime.jl for profiling

const STRICT = true

struct Buf
    iob::IOBuffer
end

Buf(b::Array{UInt8,1})  = Buf(IOBuffer(b))
Buf(s::IOStream)        = Buf(IOBuffer(read(s)))

struct NotImplementedYetError <: Exception
    msg::String
end
NotImplementedYetError() = NotImplementedYetError("something is not yet implemented..")
Base.showerror(io::IO, e::NotImplementedYetError) = print(io, "Not Yet Implemented: ", e.msg)


abstract type AbstractTag end 
mutable struct Tag{T}
    class::UInt8
    constructed::Bool # PC bit
    number::UInt8
    len::Int32
    value::Array{UInt8, 1}
end

struct  Unimplemented   <:	AbstractTag	end
struct  InvalidTag      <:	AbstractTag	end
struct	RESERVED_ENC   	<:	AbstractTag	end
struct	BOOLEAN        	<:	AbstractTag	end
struct	INTEGER        	<:	AbstractTag	end
struct	BITSTRING      	<:	AbstractTag	end
struct	OCTETSTRING    	<:	AbstractTag	end
struct	NULL           	<:	AbstractTag	end
struct	OID            	<:	AbstractTag	end
struct	ODESC          	<:	AbstractTag	end
struct	ETYPE          	<:	AbstractTag	end
struct	REAL           	<:	AbstractTag	end
struct	ENUM           	<:	AbstractTag	end
struct	EMBEDDEDPDV    	<:	AbstractTag	end
struct	UTF8STRING     	<:	AbstractTag	end
struct	ROID           	<:	AbstractTag	end
struct	TIME           	<:	AbstractTag	end
struct	RESERVED_FUTURE	<:	AbstractTag	end
struct	SEQUENCE       	<:	AbstractTag	end
struct	SET            	<:	AbstractTag	end
struct  CHAR            <:  AbstractTag end
struct  PRINTABLESTRING <:  AbstractTag end
struct  IA5STRING       <:  AbstractTag end

struct  UTCTIME         <:  AbstractTag end
struct  GENTIME         <:  AbstractTag end


Tag(class, constructed, number, len, value) :: Tag{<: AbstractTag} = begin
    t = if number   == 0    Tag{RESERVED_ENC}
    elseif number   == 1    Tag{BOOLEAN}
    elseif number   == 2    Tag{INTEGER}
    elseif number   == 3    Tag{BITSTRING}
    elseif number   == 4    Tag{OCTETSTRING}
    elseif number   == 5    Tag{NULL}
    elseif number   == 6    Tag{OID}
    elseif number   == 12   Tag{UTF8STRING}
    elseif number   == 16   Tag{SEQUENCE}
    elseif number   == 17   Tag{SET}
    elseif number   == 22   Tag{IA5STRING}
    elseif number   == 23   Tag{UTCTIME}
    elseif number   == 24   Tag{GENTIME}
    #elseif number   in (18:22)   Tag{CHAR}
    elseif number   == 19   Tag{PRINTABLESTRING}
    elseif number   in (25:30)   Tag{CHAR}
    else                    Tag{Unimplemented}
    end
    t(class, constructed, number, len, value)
end

#InvalidTag() = Tag{InvalidTag}(0, 0, 0, 0, [])
Tag{InvalidTag}() = Tag{InvalidTag}(0, 0, 0, 0, [])

function Base.show(io::IO, t::Tag{T}) where {T<:AbstractTag}
    print(io, "[$(bitstring(t.class)[7:8])] ")
    len = if t.len == 0x80
        len = "indef."
    else
        t.len
    end
    print(io, "$(nameof(T)): $(value(t)) ($(len))")
end
function Base.show(io::IO, ::MIME"text/plain", ts::Array{Tag{T},1}) where {T<:AbstractTag}
    error("oh so now this show() is triggered?")
    for t in ts
        print(io, "___[$(bitstring(t.class)[7:8])] ")
        print(io, "$(nameof(T)): $(value(t)) ($(t.len))")
        print(io, "\n")
    end
end
Base.show(io::IO, t::Tag{Unimplemented}) = print(io, "Unimplemented tag $(t.number) ($(t.len))")
Base.show(io::IO, t::Tag{NULL}) where {T} = print(io, "NULL")
function Base.show(io::IO, t::Tag{BITSTRING})
    print(io, "BITSTRING: ")
    if t.constructed
        print(io, "(constr.) ")
    else
        print(io, "(prim.) $(value(t))")
    end
    print(io, " ($(t.len))")
end
value(t::Tag{T}) where {T} = "**RAW**: $(t.value)"

value(t::Tag{RESERVED_ENC}) = ""
value(t::Tag{SEQUENCE}) = ""
value(t::Tag{SET}) = ""
# FIXME DER is stricter for BOOLEANs than this
# all bits should be 1 for true
value(t::Tag{BOOLEAN}) = t.value[1] != 0 
value(t::Tag{PRINTABLESTRING}) = String(copy(t.value))
value(t::Tag{UTCTIME}) = String(copy(t.value))
value(t::Tag{GENTIME}) = String(copy(t.value))
value(t::Tag{UTF8STRING}) = String(copy(t.value))
value(t::Tag{IA5STRING}) = String(copy(t.value))
function value(t::Tag{INTEGER}) where {T}
    if t.len > 5
        "$(t.len * 8)bit integer" #FIXME
    else
        reinterpret(Int64, resize!(reverse(t.value), 8))
    end
end

function value(t::Tag{BITSTRING}) where {T} 
    if t.len > 10
        "*blob*"
    elseif t.len >= 2
        bitstring(t.value[2] >> t.value[1])
    else
        "*empty*"
    end
end

function value(t::Tag{OCTETSTRING}) where {T} 
    if t.constructed
        @warn "constructed OCTETSTRING, not allowed in DER"
        #error("constructed OCTETSTRING, not allowed in DER")
        return nothing
    end

    if t.len <= 4 #TODO this is... horrible?
        # all octetstrings must be primitive (in DER), so how do we know whether we should look for
        # another (leaf) tag inside of this octetstring? for now, check the length..
        #@debug "horrible return"
        return t.value
    end

    return ""
end


function value(t::Tag{OID}) 
    if t.class == 0x02 # context specific TODO find documentation for this
        return String(copy(t.value))
    end

    buf = IOBuffer(t.value) 
    subids = Array{Int32,1}([0]) # 
    while !eof(buf)
        subid = 0
        byte = read(buf, 1)[1]
        while byte & 0x80 == 0x80 # first bit is 1
            subid = (subid << 7) | (byte & 0x7f) # take the last 7 bits
            byte = read(buf, 1)[1]
        end
        subid = (subid << 7) | (byte & 0x7f) # take the last 7 bits
        push!(subids, subid) #reinterpret(Int32, resize!(reverse(subid), 4)))
    end
    # get the first two sub identifiers:
    if subids[2] >= 120
        subids[1] = 3
        subids[2] %= 120
    elseif subids[2] >= 80
        subids[1] = 2
        subids[2] %= 80
    elseif subids[2] >= 40
        subids[1] = 1
        subids[2] %= 40
    else
        # is this possible?
        # x=0, y = subid[2] 
        # so actually we do not need to do anything
    end

    join(subids, ".")
end

function next(buf::Buf) :: Union{Tag, Nothing}
    if eof(buf.iob)
        return nothing
    end
    first_byte = read(buf.iob, 1)[1]
    tagclass    = first_byte  >> 6; # bit 8-7
    constructed = first_byte & 0x20 == 0x20 # bit 6
    tagnumber   = first_byte & 0x1f # bit 5-0
    if tagnumber == 31
        longtag = 0
        byte = read(buf.iob, 1)[1]
        while byte & 0x80 == 0x80 # first bit is 1
            longtag = (longtag << 7) | (byte & 0x7f) # take the last 7 bits
            byte = read(buf.iob, 1)[1]
        end
        tagnumber = (longtag << 7) | (byte & 0x7f) # take the last 7 bits
    end
    #if tagclass > 0 # TODO what should we do on a context-specific (0x02) class?
    #    @debug "tagclass", tagclass
    #end

    len = Int32(read(buf.iob, 1)[1])
    #if len  == 0x80
    #    @debug "jup"
    #    @warn "indefinite form, BER?"
    #end
    if len & 0x80 == 0x80 && len != 0x80
        # first bit set, but not 0x80 (Indefinite form) so we are dealing with either a
        # Definite long
        # Reserved
        
        # Reserved:
        if len == 0xff error("Reserved Length in tag?") end

        # Definite long
        octets::Array{UInt8,1} = read(buf.iob, len & 0x7f)
        res::Int64 = 0
        for o in octets
            res = (res << 8) | o
        end
        len = res # TODO can this break the stuff below? or trigger it incorrectly?
    end
    if len < 0
        @debug tagnumber
    end
    @assert(len >= 0)

    value = if len == 0x80
         @warn "indefinite form tag $(tagnumber) (decimal), not allowed in DER"
    #    # Indefinite form
    #    # this is not allowed in DER!
    #    @warn "indefinite form tag $(tagnumber) (decimal), not allowed in DER"
    #    _v = []
    #    b1 = read(buf.iob, 1)[1]
    #    indef_len = 1
    #    done = false
    #    while !done && !eof(buf.iob) #FIXME this !eof is also just to be lenient...
    #        if b1 == 0x00
    #            #@debug "got first EOC byte"
    #            b2 = read(buf.iob, 1)[1]
    #            if b2 == 0x00
    #                @debug "got second EOC byte"
    #                done = true
    #            else
    #                push!(_v, b1, b2)
    #            end
    #        else
    #            push!(_v, b1)
    #        end
    #        b1 = read(buf.iob, 1)[1]
    #        indef_len += 1
    #    end
    #    # we keep len == 0x80 so we know we are dealing with an indef length val
    #    # nested indef length things are troublesome..
    #    #len = indef_len
    #    _v
    
        read(buf.iob)
    elseif !constructed
        read(buf.iob, len)
    else
        #error("should we get here?") TODO look into this
        read(buf.iob, len)
    end
    return Tag(tagclass, constructed, tagnumber, len, value)
end

function next!(buf::Buf) :: Union{Tag, Nothing}
    if eof(buf.iob)
        return nothing
    end
    first_byte = read(buf.iob, 1)[1]
    tagclass    = first_byte  >> 6; # bit 8-7
    constructed = first_byte & 0x20 == 0x20 # bit 6
    tagnumber   = first_byte & 0x1f # bit 5-0
    if tagnumber == 31
        longtag = 0
        byte = read(buf.iob, 1)[1]
        while byte & 0x80 == 0x80 # first bit is 1
            longtag = (longtag << 7) | (byte & 0x7f) # take the last 7 bits
            byte = read(buf.iob, 1)[1]
        end
        tagnumber = (longtag << 7) | (byte & 0x7f) # take the last 7 bits
    end
    #if tagclass > 0 # TODO what should we do on a context-specific (0x02) class?
    #    @debug "tagclass", tagclass
    #end

    lenbyte = Int32(read(buf.iob, 1)[1])
    #if len  == 0x80
    #    @debug "jup"
    #    @warn "indefinite form, BER?"
    #end
    len = lenbyte
    if lenbyte & 0x80 == 0x80 && lenbyte != 0x80
        # first bit set, but not 0x80 (Indefinite form) so we are dealing with either a
        # Definite long
        # Reserved
        
        # Reserved:
        if lenbyte == 0xff
            @warn "Reserved Length in tag?"
            return Tag{InvalidTag}()
        end
        #@debug "definite long form"

        # Definite long
        octets::Array{UInt8,1} = read(buf.iob, lenbyte & 0x7f)
        res::Int64 = 0
        for o in octets
            res = (res << 8) | o
        end
        len = res # TODO can this break the stuff below? or trigger it incorrectly?
    end
    if len < 0
        #@warn "negative length tag $(len) == $(bitstring(len))", tagnumber
        #error("negative length")
        return Tag{InvalidTag}()
    end
    if len > buf.iob.size - buf.iob.ptr
        #@warn "length goes beyond end of buffer, returning InvalidTag"
        return Tag{InvalidTag}()
    end
    @assert(len >= 0)

    value = if lenbyte == 0x80
        #@warn "indef len, not reading value"
        []
    elseif tagnumber == 16
        #@debug "next! for SEQUENCE, _not_ reading value"
        []
    #elseif tagnumber == 0x03 || tagnumber == 0x04
    #    #lookahead = read(buf.iob, 1)[1]
    #    @debug "next! for BITSTRING/OCTETSTRING, _not_ reading value"
    #    []
    elseif !constructed
        #@debug "primitive $(tagnumber), reading value of len $(len)"
        read(buf.iob, len)
    else
        #@warn "constructed, def len, NOT reading value, but should we get here?"
        #read(buf.iob, len)
        []
    end
    return Tag(tagclass, constructed, tagnumber, len, value)
end

function parse_file(fn::String, maxtags=0)
    fd = open(fn)
    buf = DER.Buf(fd)
    tag = DER.next(buf)
    println(tag)
    while !isnothing(tag) && (maxtags==0 || tagcount < maxtags)
        tag = DER.next(buf)
        println(tag)
    end
    close(fd)
end

function _parse(tag, nested_indefs::Integer = 0) :: Node
    me = Node(tag)
    #@debug tag

    # TODO check whether the && constructed is described somewhere
    # read up on tags, explicit vs implicit etc
    if isa(tag, Tag{SEQUENCE}) || isa(tag, Tag{SET}) || (isa(tag, Tag{RESERVED_ENC}) && tag.constructed)
        if tag.len == 0x80
            @debug "actual len for", tag.number*1, "instead of 0x80:", length(tag.value)
            subtag = next(DER.Buf(tag.value))
            @debug "subtag", subtag
           # indef length,  
        end
        subbuf = DER.Buf(tag.value)
        while !eof(subbuf.iob)
            subtag = DER.next(subbuf)
            if !isa(subtag, Tag{Unimplemented})
                ASN.append!(me, _parse(subtag))
            else
                @debug "trying to parse subtag of", tag
                @debug "got Unimplemented"
            end
        end
    elseif isa(tag, Tag{BITSTRING})
        skip_unused_octet = 0
        if tag.class != 0x02
            skip_unused_octet = 1
        end
        if tag.len > 2 && tag.value[1 + skip_unused_octet] == 0x30 
            # nested SEQUENCE in this BITSTRING
            subbuf = DER.Buf(tag.value[1 + skip_unused_octet:end])
            subtag = DER.next(subbuf)
            ASN.append!(me, _parse(subtag))
        end
    elseif isa(tag, Tag{OCTETSTRING})
        subbuf = DER.Buf(tag.value[1:end])
        done = false
        subtag = DER.next(subbuf)
        if isa(subtag, Tag{OCTETSTRING}) && subtag.class != 0x02
            ASN.append!(me, Node(subtag))
        elseif tag.len >= 4 # TODO same horrible stuff as above
            ASN.append!(me, _parse(subtag))
        end
    end
    return me
end

function _parse!(tag, buf, indef_len = 0, max_read = 0) :: Node
    #@debug tag
    me = Node(tag)
    if isa(tag, Tag{SEQUENCE}) || isa(tag, Tag{SET}) ||
        ((isa(tag, Tag{RESERVED_ENC}) || isa(tag, Tag{OCTETSTRING}) || isa(tag, Tag{BITSTRING})) && tag.constructed)
        if tag.len == 0x80
            #@debug "indef len, level $(indef_len), whiling inside", tag
            my_indef_len_level = indef_len
            indef_len += 1
            #@debug "$(indef_len) > $(my_indef_len_level)?"
            while indef_len > my_indef_len_level && !eof(buf.iob) #FIXME eof should not be necessary
                #@debug "inner $(indef_len) > $(my_indef_len_level)?"
                subtag = DER.next!(buf)
                if !isa(subtag, Tag{Unimplemented})
                    if isa(subtag, Tag{RESERVED_ENC} )&& subtag.len == 0
                        indef_len -= 1
                        #@debug "got EOC byte at $(buf.iob.ptr)! doing indef_len -=1 == $(indef_len)"
                        break
                    else
                        #@debug "appending", subtag, "to", me
                        ASN.append!(me, _parse!(subtag, buf, indef_len))
                    end
                else
                    indef_len -= 1
                    @debug "(indef) trying to parse subtag of", tag
                    @debug "got Unimplemented"
                end
            end
        else
            #@debug "def len, whiling inside", tag
            offset = buf.iob.ptr
            #@debug "offset $(offset) until $(offset+tag.len)"
            while buf.iob.ptr < offset+tag.len && !eof(buf.iob) 
                #@debug "in while at $(buf.iob.ptr)"
                subtag = DER.next!(buf)
                #@debug "got subtag", subtag
                if !isa(subtag, Tag{Unimplemented})
                    ASN.append!(me, _parse!(subtag, buf, indef_len))
                else
                    #@debug "got Unimplemented at $(buf.iob.ptr), tagnumber | tagclass:", subtag.number | subtag.class
                    #buf.iob.ptr -= 1
                    #dbg = read(buf.iob, max_read) 
                    #@debug "discarding", dbg
                end
            end


        end
    #elseif isa(tag, Tag{BITSTRING})
    #    #@debug "in BITSTRING of len", tag.len
    #    #dbg = read(buf.iob, 2)
    #    #buf.iob.ptr -= 2
    #    #@debug "first 2 bytes of BITSTRING:", dbg
    #    skip_unused_octet = 0
    #    if tag.class != 0x02
    #        @warn "tag.class is not 0x02 .."
    #        skip_unused_octet = 1
    #    else
    #        @warn "tag.class is 0x02 .."
    #    end
    #    #if tag.len > 2 && tag.value[1 + skip_unused_octet] == 0x30 
    #    lookahead = read(buf.iob, 1+ skip_unused_octet)[end]
    #    buf.iob.ptr -= 1 # TODO -= 1 or 1+skip_unused_octet ? 
    #    @debug "lookahead", lookahead
    #    if tag.len > 2 && lookahead == 0x30 
    #        # nested SEQUENCE in this BITSTRING
    #        #subbuf = DER.Buf(tag.value[1 + skip_unused_octet:end])
    #        subtag = DER.next!(buf)
    #        @debug "calling _parse! for subtag of BITSTRING, max_read:", tag.len
    #        ASN.append!(me, _parse!(subtag, buf, tag.len))
    #    else
    #        @debug "no SEQUENCE in this BITSTRING, filling .value"
    #        tag.value = read(buf.iob, tag.len)
    #    end
    elseif isa(tag, Tag{OCTETSTRING})
        # primitive OCTETSTRING, but we do check for a nested SEQUENCE
        # because it is primitive, the tag.value has been set
        # and the bytes have been read from buf already

        # TODO perhaps we should only do this for specific files
        # e.g. in .cer but not in .roa ?
        # or, really make this a second pass thingy
        if tag.len > 0 && tag.value[1] == 0x30
            #@debug "tag.value for this OCTETSTRING contains SEQUENCE"
            subbuf = DER.Buf(tag.value)
            subtag = DER.next!(subbuf)
            if isa(tag, Tag{InvalidTag})
                @warn "got an InvalidTag, so, NOT an nested SEQUENCE in this OCTETSTRING?"
            elseif isa(tag, Tag{Unimplemented})
                @warn "in nested OCTETSTRING, got Unimplemented"
            else
                ASN.append!(me, _parse!(subtag, subbuf, indef_len))
            end
        end



        #subtag = DER.next!(buf)
        #@debug "subtag in this OCTETSTRING:", subtag
        #if (isa(subtag, Tag{OCTETSTRING}) || isa(subtag, Tag{SEQUENCE})) && subtag.class != 0x02
        #    @debug "got OCTETSTRING or SEQUENCE in OCTETSTRING"
        #    #ASN.append!(me, Node(subtag))
        #    ASN.append!(me, _parse!(subtag, buf))
        #else
        #    @debug "setting value for OCTETSTRING"
        #    tag.value = read(buf.iob, tag.len)
        #end
    else
        #@debug "nothing special for", tag
    end
    return me
end

function parse_file_recursive(fn::String) 
    fd = open(fn)
    buf = DER.Buf(fd)
    close(fd)
    #tag = DER.next(buf)
    #tree = _parse(tag)
    #tree
    tag = DER.next!(buf)
    indef_len = if tag.len == 0x80
        1
    else
        0
    end

    _parse!(tag, buf, indef_len)
end


end #module
