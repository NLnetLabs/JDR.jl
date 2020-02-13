module DER

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
struct Tag{T}
    class::UInt8
    constructed::Bool # PC bit
    number::UInt8
    len::Int32
    value::Array{UInt8, 1}
end

struct  Unimplemented   <:	AbstractTag	end
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
#struct  CHAR            <:  AbstractTag end
struct  PRINTABLESTRING <:  AbstractTag end

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
    elseif number   == 16   Tag{SEQUENCE}
    elseif number   == 17   Tag{SET}
    elseif number   == 23   Tag{UTCTIME}
    elseif number   == 24   Tag{GENTIME}
    #elseif number   in (18:22)   Tag{CHAR}
    elseif number   == 19   Tag{PRINTABLESTRING}
    elseif number   in (25:30)   Tag{CHAR}
    else                    Tag{Unimplemented}
    end
    t(class, constructed, number, len, value)
end

function Base.show(io::IO, t::Tag{T}) where {T<:AbstractTag}
    print(io, "[$(bitstring(t.class)[7:8])] ")
    print(io, "$(nameof(T)): $(value(t)) ($(t.len))")
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

value(t::Tag{SEQUENCE}) = nothing
value(t::Tag{SET}) = nothing
value(t::Tag{BOOLEAN}) = t.value[1] != 0
value(t::Tag{PRINTABLESTRING}) = String(t.value)
value(t::Tag{INTEGER}) = reinterpret(Int64, resize!(reverse(t.value), 8)) #FIXME this fails for e.g. the 2048bit key material

function value(t::Tag{BITSTRING}) where {T} 
    # TODO ask martin:
    # in the ripe TA .cer, there seems to be a SEQUENCE inside a _primitive_
    # BITSTRING. Shouldn't that be a _constructed_ BITSTRING then?

    if t.constructed
        return nothing
    end

    unused = t.value[1]

    if STRICT
        return t.value[2:end]
    end

    buf = DER.Buf(t.value[2:end])

    # we should actually only return the t.value, because this is a primitive..
    # but for now, let's be lenient
    
    subtags = Array{Tag{<:AbstractTag},1}()
    while !eof(buf.iob)
        subtag = next(buf)
        push!(subtags, subtag)
    end
    #display(subtags)
    return subtags
end

function value(t::Tag{OCTETSTRING}) where {T} 
    # TODO
    # if we want to be lenient here, we shoot ourselves in the foot:
    # if we 'ignore' the constructed bit, and we simply 
    # 

    #@debug "tag: ", t.number
    #@debug "len: ", t.len
    #@debug "constructed?: ", t.constructed
    if t.constructed
        @debug "constructed OCTETSTRING, not allowed in DER"
        return nothing
    end

    # So, in DER the encoding of an octetstring MUST be primitive
    # but there will be actual leafs inside of it
    # 
    #if STRICT
    #    @debug "STRICT octetstring"
    #    return t.value[1:end]
    #else
    #    @debug "non STRICT octetstring"
    #end

    if t.len <= 4 #TODO this is... horrible?
        # all octetstrings must be primitive (in DER), so how do we know whether we should look for
        # another (leaf) tag inside of this octetstring? for now, check the length..
        @debug "horrible return"
        return t.value
    end

    # TODO for now, we simply return the value
    # in order to do more complex stuff, we need to actually build up a tree
    return t.value

    buf = DER.Buf(t.value[1:end])

    # we should actually only return the t.value, because this is a primitive..
    # but for now, let's be lenient
    
    subtag = next(buf)
    if isa(subtag, Tag{Unimplemented})
        @debug "subtag Unimplemented"
        return t.value
    else
        @debug "found subtag number ", subtag.number
        return subtag
    end
end


function value(t::Tag{OID}) 
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
        #throw(NotImplementedYetError("long form tag numbers"))
        byte = read(buf.iob, 1)[1]
        while byte & 0x80 == 0x80 # first bit is 1
            longtag = (longtag << 7) | (byte & 0x7f) # take the last 7 bits
            byte = read(buf.iob, 1)[1]
        end
        tagnumber = (longtag << 7) | (byte & 0x7f) # take the last 7 bits
    end

    len = Int32(read(buf.iob, 1)[1])
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

    #TODO decide whether we always consume the value (so also in case of
    #SEQUENCE and SET), at the cost of losing stream-based parsing..
    value = if len == 0x80
        # Indefinite form
        # this is not allowed in DER!
        @debug "indefinite form tag $(tagnumber) (decimal), not allowed in DER"
        _v = []
        b1 = read(buf.iob, 1)[1]
        done = false
        while !done && !eof(buf.iob) #FIXME this eof! is also just to be lenient...
            if b1 == 0x00
                b2 = read(buf.iob, 1)[1]
                if b2 == 0x00
                    done = true
                else
                    push!(_v, b1, b2)
                end
            else
                push!(_v, b1)
            end
            b1 = read(buf.iob, 1)[1]
        end
        _v
    elseif !constructed  #|| tagnumber == 0x23
        read(buf.iob, len)
    else
        Array{UInt8}([]) 
    end
    #if length(value) > 2 @debug value[end-1:end] end
    return Tag(tagclass, constructed, tagnumber, len, value)
end

function parse_file(fn::String, maxtags=0)
    buf = DER.Buf(open(fn))
    println("parsing file ", fn)
    tag = DER.next(buf)
    println(tag)
    while !isnothing(tag) && (maxtags==0 || tagcount < maxtags)
        tag = DER.next(buf)
        println(tag)
    end
    println("done!")
end


end #module
