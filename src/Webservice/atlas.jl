using DataFrames
using StatsBase

function fetch_measurements() :: NamedTuple
    Atlas.set_api_key("84d31224-db05-422c-b5d0-0b886b73f87d")
    msms = Atlas.get_measurement(Dict("tags"=>"rpki-repositories-bundle", "status" => "Ongoing", "page_size" => "500" ))
    @info "got $(msms.count) measurements"
    msms
end

function fetch_results(msms::NamedTuple) #:: Vector{NamedTuple}
    #@info typeof(Atlas.get_results(Atlas.Measurement(msms.results[1].id)))
    
    #[Atlas.get_results(Atlas.Measurement(msm.id)) for msm in msms.results]
    asyncmap(Atlas.get_results, [Atlas.Measurement(msm.id) for msm in msms.results], ntasks=10)
end

function create_df(results::Array) :: DataFrame
    @info length(results)
    df = DataFrame(
        msm_id=Int[],
        prb_id=Int[],
        endtime=Int[],
        af=Int[],
        src_addr=String[],
        dst_addr=String[],
        dst_name=String[],
        proto=String[],
        result=Any[],
        rtt_median=Float64[],
        error=Union{Nothing,String}[]
    )
    allowmissing!(df);
    
    for msm in results
        @assert length(msm) > 0
        for res in msm
            try
                err = nothing
                rtt_median = missing
                rtts = if (:error in keys(res.result[1]))
                    err = res.result[1].error
                    []
                else
                    filter(e->haskey(e, :rtt) , res.result[1].result) |> 
                    @map(e->e.rtt) |> collect
                end
                if isempty(rtts) 
                    if isnothing(err)
                        err = "no response? $(string(res.result[1].result))"
                    end
                else
                    rtt_median = quantile(rtts, 0.5)
                end

                push!(df, (
                    res.msm_id,
                    res.prb_id,
                    res.endtime,
                    res.af,
                    get(res, :src_addr, missing),
                    get(res, :dst_addr, missing),
                    res.dst_name,
                    res.proto,
                    rtts,
                    rtt_median,
                    err
                    )
                )
            catch e
                @error e
                @show res
                return
            end
        end
    end
    df
end

# measurement results lack the dst_port, we join the results with the original measurement definition to get those
function join_msm_def(df::DataFrame, msms::NamedTuple) :: DataFrame
    msms_df = DataFrame(
        msm_id=Int[],
        port=Int[]
        )
    for msm in msms.results
        push!(msms_df, (
                msm.id,
                msm.port)
        )
    end;
    innerjoin(df, msms_df, on = :msm_id)
end

function only_healthy(df::AbstractDataFrame) :: DataFrame
    # try to select only healthy anchors (ha)
    # first, calculate the 90 percentile of rtts and the number of results
    ha =
        combine(
            groupby(dropmissing(df), [:prb_id]),
            :rtt_median => (e -> quantile(e, 0.90)) => :rtt_mm,
            nrow => :no
    )
    # then use those to filter outliers:
    # very high rtts or a low number of results indicate anchors having network issues
    ha = ha[
        (ha.rtt_mm .< quantile(ha.rtt_mm, 0.95)) .&
        (ha.no .>= quantile(ha.no, 0.5))
    , :]

    df[∈(ha.prb_id).(df.prb_id), :]
end

# take most recent measurements since sec
function recent(df::AbstractDataFrame, sec::Int=600)
    #df[∈(sample(only_healthy(df).prb_id, n, replace=false)).(df.prb_id), :]
    df[df.endtime .> (maximum(df.endtime) - sec), :]
end



function _repos_with_issues(df::AbstractDataFrame)
    _d = only_healthy(df)
    total_prbs = _d.prb_id |> unique |> length
    problem_repos = combine(
        groupby(_d[length.(_d.result) .< 3, :], [:dst_name, :af, :port, :msm_id]),
        :prb_id => (p -> (length(unique(p))) // total_prbs) => :problem_ratio,

    )
    problem_repos[problem_repos.problem_ratio .> 0.5, :]
    problem_repos[!, :nicename] = map(r->(r.port == 873 ? "rsync" : "rrdp") .* string(r.af), eachrow(problem_repos))
    problem_repos[problem_repos.problem_ratio .> 0.2, [:dst_name, :nicename, :msm_id]]
end

function ppstatus(df::AbstractDataFrame)
    all_repos = Dict([repo => [] for repo in  unique(df.dst_name)])
    
    problem_repos = Dict(
        [key.dst_name => 
            [(proto=row.nicename, atlas_msm=row.msm_id) for row in eachrow(gdf)]
        for (key, gdf) in pairs(groupby(_repos_with_issues(df), :dst_name))
    ])
    
    merge(all_repos, problem_repos) # |> JSON2.write
end
