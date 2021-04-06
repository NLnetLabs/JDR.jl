using Logging
using LoggingExtras
using Dates;

const date_format = "yyyy-mm-dd HH:MM:SS"

timestamp_logger(logger) = TransformerLogger(logger) do log
	merge(log, (; message = "$(Dates.format(now(), date_format)) $(log.message)"))
end

using Base.CoreLogging: global_logger,
        LogLevel, BelowMinLevel, Debug, Info, Warn, Error, AboveMaxLevel
import Base.CoreLogging: AbstractLogger, SimpleLogger,
        handle_message, shouldlog, min_enabled_level, catch_exceptions

struct CleanLogger <: AbstractLogger 
    logger::SimpleLogger
end


function CleanLogger(path::AbstractString; kwargs...)
    filehandle = open(path, "a")
    CleanLogger(filehandle; kwargs...)
end

function CleanLogger(filehandle::IOStream)
    CleanLogger(SimpleLogger(filehandle, BelowMinLevel))
end

shouldlog(::CleanLogger, arg...) = true
min_enabled_level(::CleanLogger) = BelowMinLevel
catch_exceptions(cleanlogger::CleanLogger) = catch_exceptions(cleanlogger.logger)

function handle_message(cleanlogger::CleanLogger, level, message, _module,
                        group, id, filepath, line; maxlog=nothing, kwargs...)
    buf = IOBuffer()
    iob = IOContext(buf, cleanlogger.logger.stream)
    msglines = split(chomp(string(message)), '\n')
    println(iob, msglines[1])
    for l in msglines[2:end]
        println(iob, repeat(' ', length(date_format)+1), l)
    end
    write(cleanlogger.logger.stream, take!(buf))
    flush(cleanlogger.logger.stream)
    nothing
end

function init_logger() 
    if !(global_logger() isa TeeLogger)
        JDRlogger = TeeLogger(
                              global_logger(),
                              timestamp_logger(MinLevelLogger(CleanLogger(JDR.CFG["webservice"]["logfile"]), Logging.Warn)),
                             );
        global_logger(JDRlogger)
    end
end

