module PrefixTrees

    using IPNets
    import Base: setindex!, get, getindex, values, keys, iterate, length
    export PrefixTree, setindex!, subtree, getindex, values, firstparent, iterate

    mutable struct PrefixTree{T}
        vals::Union{Nothing, Vector{T}}
        zero::Union{Nothing, PrefixTree{T}}
        one::Union{Nothing, PrefixTree{T}}
        is_key::Bool
        key::Union{Nothing, IPNet}
        len::Int

        function PrefixTree{T}() where T
            self = new{T}()
            self.vals = nothing
            self.zero = nothing
            self.one = nothing
            self.is_key = false
            self.key = nothing
            self.len = 0
            self
        end

    end

    PrefixTree() = PrefixTree{Any}()

    # if need be, we can optimize the bitstring() here
    # https://discourse.julialang.org/t/convert-integer-to-bits-array/26663/7
    # though the gains at this moment are relatively small
    function prefix_to_bits(prefix::IPv6Net)
        bitstring(UInt128(prefix.netaddr))[1:prefix.netmask]
    end

    function prefix_to_bits(prefix::IPv4Net)
        bitstring(UInt32(prefix.netaddr))[1:prefix.netmask]
    end


    function length(t::PrefixTree{T}) where T
        t.len
    end

    function setindex!(t::PrefixTree{T}, val::T, key::IPNet) where T
        node = t
        for b in prefix_to_bits(key)
            if b == '0'
                if isnothing(node.zero)
                    node.zero = PrefixTree{T}()
                end
                node = node.zero
            else
                if isnothing(node.one)
                    node.one = PrefixTree{T}()
                end
                node = node.one
            end
        end
        if node.is_key
            @assert node.key == key
        else
            t.len += 1
        end
        node.is_key = true
        node.key = key

        if isnothing(node.vals)
            node.vals = [val]
        else
            push!(node.vals, val)
        end
    end


    function subtree(t::PrefixTree{T}, key::IPNet) where T
        node = t
        #for b in bitstring(key)
        for b in prefix_to_bits(key)
            if b == '0'
                if isnothing(node.zero)
                    return nothing
                else
                    node = node.zero
                end
            else
                if isnothing(node.one)
                    return nothing
                else
                    node = node.one
                end
            end
        end
        node
    end

    function firstparent(t::PrefixTree{T}, key::IPNet) where T
        node = t
        res = nothing
        for b in prefix_to_bits(key)
            if b == '0'
                if isnothing(node.zero)
                    break
                else
                    if node.is_key
                        res = node
                    end
                    node = node.zero
                end
            else
                if isnothing(node.one)
                    break
                else
                    if node.is_key
                        res = node
                    end
                    node = node.one
                end
            end
        end
        if node.is_key
            res = node
        end
        return res
    end

        
    function getindex(t::PrefixTree, key::IPNet)
        node = subtree(t, key)
        if !isnothing(node) && node.is_key
            return node.vals
        end
        #throw(KeyError("no key '$key'"))
        return nothing
    end

    function get(t::PrefixTree, key::IPNet)
        node = subtree(t, key)
        if !isnothing(node) && node.is_key
            return first(node.vals)
        end
        #throw(KeyError("no key '$key'"))
        return nothing
    end

    #FIXME
    # prefix initial value depends on IPv4Net vs IPv6Net
    function keys(t::PrefixTree, prefix::IPNet=IPNet("::0/0"), found=IPNet[])
        if t.is_key
            push!(found, prefix)
        end
        if !isnothing(t.zero)
            keys(t.zero, prefix << 1, found)
        end
        if !isnothing(t.one)
            keys(t.one, prefix << 1 + 1, found)
        end
        found
    end

    function values(::Nothing)
        return []
    end

    function values(t::PrefixTree{T}, found=T[]) where T
        if t.is_key
            append!(found, t.vals)
        end
        if !isnothing(t.zero)
            values(t.zero, found)
        end
        if !isnothing(t.one)
            values(t.one, found)
        end
        found

    end


    # we return key -> [vals]
    function iterate(t::PrefixTree{T}) where T
        found = false
        current = t
        to_check = PrefixTree{T}[]
        while !found
            #if length(to_check) > 1
            #    @debug "in while iterate1, to_check len" length(to_check)
            #end
            if current.is_key
                item = (current.key => current.vals)
                if !isnothing(current.zero)
                    #@debug "pushing zero"
                    push!(to_check, current.zero)
                end
                if !isnothing(current.one)
                    #@debug "pushing one"
                    push!(to_check, current.one)
                end
                #@debug "returning actual item!"
                return (item, to_check)
            else
                #@debug "not a key .."
                if !isnothing(current.zero)
                    #@debug "pushing zero"
                    push!(to_check, current.zero)
                end
                if !isnothing(current.one)
                    #@debug "pushing one"
                    push!(to_check, current.one)
                end
                if isempty(to_check)
                    return nothing
                end
                #@debug "setting current to popfirst!"
                current = popfirst!(to_check)
            end
            #@debug "next while"
        end
    end
    # state::Union{Nothing,Vector{PrefixTree}} ?
    function iterate(t::PrefixTree{T}, to_check) where T
        if isnothing(to_check) || isempty(to_check)
            return nothing
        end
        found = false
        current = popfirst!(to_check)
        while !found 
            #if length(to_check) > 1
            #    @debug "in while iterate2, to_check len" length(to_check)
            #end
            if current.is_key
                #@debug "current.is_key true"
                item = (current.key => current.vals)
                if !isnothing(current.zero)
                    #@debug "pushing zero"
                    push!(to_check, current.zero)
                end
                if !isnothing(current.one)
                    #@debug "pushing one"
                    push!(to_check, current.one)
                end
                #@debug "returning actual item!"
                return (item, to_check)
            else
                #@debug "not a key .."
                if !isnothing(current.zero)
                    #@debug "pushing zero"
                    push!(to_check, current.zero)
                end
                if !isnothing(current.one)
                    #@debug "pushing one"
                    push!(to_check, current.one)
                end
                if isempty(to_check)
                    return nothing
                end
                #@debug "setting current to popfirst!"
                current = popfirst!(to_check)
            end
            #@debug "next while"
        end
        @error "should I end up here?"
        @debug length(to_check)
    end
    
end
