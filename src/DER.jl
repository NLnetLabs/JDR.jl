module DER



#struct Buf
#    buffer::Array{UInt8, 1}
#    index::UInt64
#    Buf(b) = new(b, 1)
#end

struct Buf
    iob::IO
end

Buf(b::Array{UInt8,1}) = Buf(IOBuffer(b))

struct NotImplementedYetError <: Exception end
abstract type AbstractTag end 
struct Tag{T}
    class::UInt8
    constructed::Bool # PC bit
    number::UInt8
    len::Int32
    value::Array{UInt8, 1}
end

struct INTEGER          <: AbstractTag end
struct SEQUENCE         <: AbstractTag end
struct Unimplemented    <: AbstractTag end


Tag(class, constructed, number, len, value) :: Tag{<: AbstractTag} = begin
    # todo make a Type t from this ifelse
    # afterwards, call t(class, constructed ...)
    # e.g. t = Tag{INTEGER} ; t(class, constructed, ...)
    t = if number   == 0    Tag{RESERVED}
    elseif number   == 1    Tag{BOOL}
    elseif number   == 2    Tag{INTEGER}
    elseif number   == 3    Tag{BITSTRING}
    elseif number   == 16   Tag{SEQUENCE}
    else                    Tag{Unimplemented}
    end
    t(class, constructed, number, len, value)
end

function print_tag(tag::Tag)
    println("printing Tag.. shoulw this be triggered?")
end

print_tag(t::Tag{SEQUENCE}) = println("SEQUENCE: ")
print_tag(t::Tag{INTEGER}) = println("INTEGER: ")

#print(tag::INTEGER)

function next(buf::Buf) :: Union{Tag, Nothing}
    if eof(buf.iob)
        return Nothing
    end
    first_byte = read(buf.iob, 1)[1]
    tagclass    = first_byte  >> 6; # bit 8-7
    PC          = first_byte & 0x20 == 0x20 # bit 6
    tagnumber   = first_byte & 0x1f # bit 5-0
    if tagnumber == 31
        throw(NotImplementedYetError())
    end
    len = Int32(read(buf.iob, 1)[1])
    value = if !PC
        read(buf.iob, len)
    else
        Array{UInt8}([]) 
    end
    return Tag(tagclass, PC, tagnumber, len, value)
end

function parse_file(fn::String)

end


end #module
