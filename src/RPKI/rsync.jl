module Rsync

using JDR: CFG

function fetch_all(ca_host::AbstractString, ca_path::AbstractString)
    module_dir = splitpath(ca_path)[1]
    output_dir = joinpath(CFG["rpki"]["rsync_data_dir"], ca_host, module_dir)
    cmd = `rsync --delete --contimeout=5 --timeout=5 --mkpath --relative --archive rsync://$ca_host/$module_dir $output_dir`
    #@debug cmd
    try
        run(cmd)
    catch e
        @error "Could not fetch from rsync://$(ca_host)/$(ca_path): ", e
    end
end

function fetch_ta_cer(url::AbstractString, output_fn::AbstractString)
    cmd = `rsync --mkpath --archive $url $output_fn`
    #@debug cmd
    try
        run(cmd)
    catch e
        @error "Could not retrieve TA cer from $(url): ", e
    end
end

end
