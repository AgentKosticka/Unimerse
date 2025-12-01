using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace UnimerseLib
{
    /// <summary>
    /// Defines the available logging backends.
    /// </summary>
    public enum LogType
    {
        Basic,
        SpectreConsole,
        Custom,
        None
    }

    /// <summary>
    /// Represents the severity associated with a log entry.
    /// </summary>
    public enum LogLevel
    {
        Info = 1, // Will be logged if accepted level is Info or lower.
        Warning = 2, // Will be logged if accepted level is Warning or lower.
        Error = 3, // Will always be logged.
        Debug = 0, // Will be logged only if accepted level is Debug.
        Required = 4 // Should always be logged.
    }

    /// <summary>
    /// Coordinates formatting and routing of log entries to the configured output.
    /// </summary>
    public class Logger(string prefix, string? style = null)
    {
        public string? defaultStyle = style;
        public string defaultPrefix = prefix;
        public LogType logType = LogType.SpectreConsole;
        public event Action<string, string?, string?, bool>? OnMessageLogged;
        public LogLevel acceptedLevel = LogLevel.Info;

        public Channel<Log>? logChannel;
        public bool UseChannel { get; private set; }

        /// <summary>
        /// Writes a log entry respecting the current log level and output mode.
        /// </summary>
        public void LogMessage(Log log)
        {
            if (log.Level < acceptedLevel) return;

            log.LoadDefaultsFromLogger(this);

            switch (logType)
            {
                case LogType.None:
                    break;
                case LogType.Custom:
                    OnMessageLogged?.Invoke(log.Message, log.Prefix, log.Style, log.Brackets);
                    break;

                case LogType.SpectreConsole when !UseChannel:
                    AnsiConsole.MarkupLine(log.Format(logType));
                    break;
                case LogType.Basic when !UseChannel:
                    Console.WriteLine(log.Format(logType));
                    break;

                case LogType.Basic when UseChannel:
                case LogType.SpectreConsole when UseChannel:
                    logChannel!.Writer.TryWrite(log); // logChannel is guaranteed to be not null if useChannel is true because of EnableChannel method
                    break;

            }
        }
        /// <summary>
        /// Formats a message using the logger's defaults without emitting it.
        /// </summary>
        public string Format(string message, string? prefix = null, string? style = null, bool brackets = true)
        {
            prefix ??= defaultPrefix;
            style ??= defaultStyle;

            if (brackets && prefix[0] != '[') prefix = $"[[{prefix}]]";

            return $"[{style ?? ""}]{prefix ?? ""}[/] {message}";
        }

        /// <summary>
        /// Enables asynchronous logging via a shared channel.
        /// </summary>
        public void EnableChannelMode()
        {
            logChannel ??= Channel.CreateUnbounded<Log>();
            UseChannel = true;
        }
        /// <summary>
        /// Disables channel-backed logging and reverts to direct writes.
        /// </summary>
        public void DisableChannelMode()
        {
            UseChannel = false;
        }
    }
    /// <summary>
    /// Represents a structured log message with optional formatting metadata.
    /// </summary>
    public class Log(string message, string? prefix = null, string? style = null, bool brackets = true, LogLevel logLevel = LogLevel.Info)
    {
        public readonly string Message = message;
        public string? Prefix = prefix;
        public string? Style = style;
        public readonly bool Brackets = brackets;
        public readonly LogLevel Level = logLevel;

        /// <summary>
        /// Maps log levels to their Spectre.Console formatted prefixes.
        /// </summary>
        public readonly static Dictionary<LogLevel, string> LogLevelPrefix = new()
        {
            { LogLevel.Info, "[honeydew2][[Info]][/] " },
            { LogLevel.Warning, "[darkorange3][[Warning]][/] " },
            { LogLevel.Error, "[red][[Error]][/] " },
            { LogLevel.Debug, "[grey50][[Debug]][/] " },
            { LogLevel.Required, "" }
        };

        private string? _temporaryPart = null;
        private readonly Lock @temporaryPartLock = new();

        public string? TemporaryPart
        {
            get
            {
                lock (@temporaryPartLock) return _temporaryPart;
            }
            set
            {
                lock (@temporaryPartLock) _temporaryPart = value;
            }
        }

        /// <summary>
        /// Applies default prefix and style values from the owning logger.
        /// </summary>
        public void LoadDefaultsFromLogger(Logger logger)
        {
            Prefix ??= logger.defaultPrefix;
            Style ??= logger.defaultStyle;
        }

        /// <summary>
        /// Renders the log entry using the specified output mode.
        /// </summary>
        public string Format(LogType logType)
        {
            StringBuilder sb = new();

            switch (logType)
            {
                case LogType.None:
                    return "";
                case LogType.Custom:
                    throw new InvalidOperationException("Custom log type does not support formatting.");

                case LogType.SpectreConsole:
                    sb.Append(LogLevelPrefix[Level]);
                    if (!string.IsNullOrEmpty(Style))
                    {
                        sb.Append($"[{Style}]");
                    }
                    if (!string.IsNullOrEmpty(Prefix))
                    {
                        string pre = Markup.Escape(Prefix);
                        if (Brackets && pre[0] != '[') pre = $"[[{pre}]]";
                        sb.Append(pre);
                    }
                    if (!string.IsNullOrEmpty(Style))
                    {
                        sb.Append($"[/] ");
                    }
                    sb.Append(Markup.Escape(Message));

                    string? temp = TemporaryPart; // Reads once in order to avoid blocking threads for too long

                    if (!string.IsNullOrEmpty(temp))
                    {
                        if (!string.IsNullOrEmpty(temp))
                        {
                            sb.Append($"[grey]{temp}[/]");
                        }
                    }

                    return sb.ToString();
                case LogType.Basic:
                    if (!string.IsNullOrEmpty(Prefix))
                    {
                        string pre = Prefix;
                        if (Brackets && pre[0] != '[') pre = $"[{pre}]";
                        sb.Append(pre);
                        sb.Append(' ');
                    }
                    sb.Append(Message);
                    return sb.ToString();

                default:
                    return Message;
            }
        }
    }
}
