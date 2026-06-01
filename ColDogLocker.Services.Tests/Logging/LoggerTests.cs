using ColDogStudios.ColDogLocker.Services.Logging;

namespace ColDogStudios.ColDogLocker.Services.Tests.Logging
{
    public class LogEntryTests
    {
        [Fact]
        public void LogEntry_CanBeInstantiated()
        {
            // Act
            var logEntry = new LogEntry();

            // Assert
            Assert.NotNull(logEntry);
        }

        [Fact]
        public void LogEntry_DefaultValues_ShouldBeCorrect()
        {
            // Act
            var logEntry = new LogEntry();

            // Assert
            Assert.Null(logEntry.Timestamp);
            Assert.Equal(string.Empty, logEntry.Level);
            Assert.Equal(string.Empty, logEntry.Message);
            Assert.Null(logEntry.Caller);
            Assert.Null(logEntry.Exception);
            Assert.Equal(string.Empty, logEntry.SessionId);
        }

        [Fact]
        public void LogEntry_Timestamp_CanBeSet()
        {
            // Arrange
            var logEntry = new LogEntry();
            var timestamp = "2026-01-13T12:34:56.789Z";

            // Act
            logEntry.Timestamp = timestamp;

            // Assert
            Assert.Equal(timestamp, logEntry.Timestamp);
        }

        [Fact]
        public void LogEntry_Level_CanBeSet()
        {
            // Arrange
            var logEntry = new LogEntry();
            var level = "Info";

            // Act
            logEntry.Level = level;

            // Assert
            Assert.Equal(level, logEntry.Level);
        }

        [Fact]
        public void LogEntry_Message_CanBeSet()
        {
            // Arrange
            var logEntry = new LogEntry();
            var message = "Test log message";

            // Act
            logEntry.Message = message;

            // Assert
            Assert.Equal(message, logEntry.Message);
        }

        [Fact]
        public void LogEntry_Caller_CanBeSet()
        {
            // Arrange
            var logEntry = new LogEntry();
            var caller = new CallerInfo { Method = "TestMethod", File = "TestFile.cs", Line = 42 };

            // Act
            logEntry.Caller = caller;

            // Assert
            Assert.NotNull(logEntry.Caller);
            Assert.Equal("TestFile.cs", logEntry.Caller.File);
        }

        [Fact]
        public void LogEntry_Exception_CanBeSet()
        {
            // Arrange
            var logEntry = new LogEntry();
            var exceptionInfo = new ExceptionInfo { Type = "InvalidOperationException", Message = "Test error" };

            // Act
            logEntry.Exception = exceptionInfo;

            // Assert
            Assert.NotNull(logEntry.Exception);
            Assert.Equal("InvalidOperationException", logEntry.Exception.Type);
        }

        [Fact]
        public void LogEntry_SessionId_CanBeSet()
        {
            // Arrange
            var logEntry = new LogEntry();
            var sessionId = "20231230_123456";

            // Act
            logEntry.SessionId = sessionId;

            // Assert
            Assert.Equal(sessionId, logEntry.SessionId);
        }

        [Fact]
        public void LogEntry_AllProperties_CanBeSetTogether()
        {
            // Arrange
            var timestamp = "2026-01-13T12:34:56.789Z";
            var level = "Error";
            var message = "An error occurred";
            var caller = new CallerInfo { Method = "TestMethod", File = "Program.cs", Line = 123 };
            var sessionId = "session_001";

            // Act
            var logEntry = new LogEntry
            {
                Timestamp = timestamp,
                Level = level,
                Message = message,
                Caller = caller,
                SessionId = sessionId
            };

            // Assert
            Assert.Equal(timestamp, logEntry.Timestamp);
            Assert.Equal(level, logEntry.Level);
            Assert.Equal(message, logEntry.Message);
            Assert.NotNull(logEntry.Caller);
            Assert.Equal("Program.cs", logEntry.Caller.File);
            Assert.Equal(sessionId, logEntry.SessionId);
        }

        [Theory]
        [InlineData("Debug")]
        [InlineData("Info")]
        [InlineData("Warning")]
        [InlineData("Error")]
        [InlineData("Fatal")]
        public void LogEntry_Level_CanBeSetToVariousLogLevels(string level)
        {
            // Arrange
            var logEntry = new LogEntry
            {
                // Act
                Level = level
            };

            // Assert
            Assert.Equal(level, logEntry.Level);
        }

        [Fact]
        public void LogEntry_Caller_CanBeNull()
        {
            // Arrange & Act
            var logEntry = new LogEntry { Caller = null };

            // Assert
            Assert.Null(logEntry.Caller);
        }

        [Fact]
        public void LogEntry_Message_CanContainSpecialCharacters()
        {
            // Arrange
            var message = "Error: File not found! @#$%^&*()";
            var logEntry = new LogEntry
            {
                // Act
                Message = message
            };

            // Assert
            Assert.Equal(message, logEntry.Message);
        }

        [Fact]
        public void LogEntry_Message_CanBeMultiline()
        {
            // Arrange
            var message = "Line 1\nLine 2\nLine 3";
            var logEntry = new LogEntry
            {
                // Act
                Message = message
            };

            // Assert
            Assert.Equal(message, logEntry.Message);
        }
    }

    public class LogLevelEnumTests
    {
        [Fact]
        public void LogLevel_ShouldHaveDebugValue()
        {
            // Act & Assert
            Assert.Equal(0, (int)LogLevel.Debug);
        }

        [Fact]
        public void LogLevel_ShouldHaveInfoValue()
        {
            // Act & Assert
            Assert.Equal(1, (int)LogLevel.Info);
        }

        [Fact]
        public void LogLevel_ShouldHaveWarningValue()
        {
            // Act & Assert
            Assert.Equal(2, (int)LogLevel.Warning);
        }

        [Fact]
        public void LogLevel_ShouldHaveErrorValue()
        {
            // Act & Assert
            Assert.Equal(3, (int)LogLevel.Error);
        }

        [Fact]
        public void LogLevel_ToString_ShouldReturnCorrectName()
        {
            // Act & Assert
            Assert.Equal("Debug", nameof(LogLevel.Debug));
            Assert.Equal("Info", nameof(LogLevel.Info));
            Assert.Equal("Warning", nameof(LogLevel.Warning));
            Assert.Equal("Error", nameof(LogLevel.Error));
            Assert.Equal("Fatal", nameof(LogLevel.Fatal));
        }

        [Theory]
        [InlineData(LogLevel.Debug, "Debug")]
        [InlineData(LogLevel.Info, "Info")]
        [InlineData(LogLevel.Warning, "Warning")]
        [InlineData(LogLevel.Error, "Error")]
        [InlineData(LogLevel.Fatal, "Fatal")]
        public void LogLevel_ToString_ShouldMatchExpectedValue(LogLevel level, string expected)
        {
            // Act
            var result = level.ToString();

            // Assert
            Assert.Equal(expected, result);
        }

        [Fact]
        public void LogLevel_AllValues_ShouldBeAccessible()
        {
            // Act
            var allLevels = Enum.GetValues<LogLevel>();

            // Assert
            Assert.Equal(5, allLevels.Length);
            Assert.Contains(LogLevel.Debug, allLevels);
            Assert.Contains(LogLevel.Info, allLevels);
            Assert.Contains(LogLevel.Warning, allLevels);
            Assert.Contains(LogLevel.Error, allLevels);
            Assert.Contains(LogLevel.Fatal, allLevels);
        }
    }

    public class CallerInfoTests
    {
        [Fact]
        public void CallerInfo_CanBeInstantiated()
        {
            // Act
            var callerInfo = new CallerInfo();

            // Assert
            Assert.NotNull(callerInfo);
        }

        [Fact]
        public void CallerInfo_Method_CanBeSet()
        {
            // Arrange
            var callerInfo = new CallerInfo();
            var method = "MyMethod";

            // Act
            callerInfo.Method = method;

            // Assert
            Assert.Equal(method, callerInfo.Method);
        }

        [Fact]
        public void CallerInfo_File_CanBeSet()
        {
            // Arrange
            var callerInfo = new CallerInfo();
            var file = "Program.cs";

            // Act
            callerInfo.File = file;

            // Assert
            Assert.Equal(file, callerInfo.File);
        }

        [Fact]
        public void CallerInfo_Line_CanBeSet()
        {
            // Arrange
            var callerInfo = new CallerInfo();
            var line = 123;

            // Act
            callerInfo.Line = line;

            // Assert
            Assert.Equal(line, callerInfo.Line);
        }

        [Fact]
        public void CallerInfo_AllProperties_CanBeSetTogether()
        {
            // Arrange & Act
            var callerInfo = new CallerInfo { Method = "TestMethod", File = "TestFile.cs", Line = 456 };

            // Assert
            Assert.Equal("TestMethod", callerInfo.Method);
            Assert.Equal("TestFile.cs", callerInfo.File);
            Assert.Equal(456, callerInfo.Line);
        }
    }

    public class ExceptionInfoTests
    {
        [Fact]
        public void ExceptionInfo_CanBeInstantiated()
        {
            // Act
            var exceptionInfo = new ExceptionInfo();

            // Assert
            Assert.NotNull(exceptionInfo);
        }

        [Fact]
        public void ExceptionInfo_Type_CanBeSet()
        {
            // Arrange
            var exceptionInfo = new ExceptionInfo();
            var type = "InvalidOperationException";

            // Act
            exceptionInfo.Type = type;

            // Assert
            Assert.Equal(type, exceptionInfo.Type);
        }

        [Fact]
        public void ExceptionInfo_Message_CanBeSet()
        {
            // Arrange
            var exceptionInfo = new ExceptionInfo();
            var message = "Something went wrong";

            // Act
            exceptionInfo.Message = message;

            // Assert
            Assert.Equal(message, exceptionInfo.Message);
        }

        [Fact]
        public void ExceptionInfo_StackTrace_CanBeSet()
        {
            // Arrange
            var exceptionInfo = new ExceptionInfo();
            var stackTrace = "at MyMethod() in Program.cs:line 42";

            // Act
            exceptionInfo.StackTrace = stackTrace;

            // Assert
            Assert.Equal(stackTrace, exceptionInfo.StackTrace);
        }

        [Fact]
        public void ExceptionInfo_AllProperties_CanBeSetTogether()
        {
            // Arrange & Act
            var exceptionInfo = new ExceptionInfo
            {
                Type = "ArgumentNullException", Message = "Argument was null", StackTrace = "at Method() in File.cs:line 99"
            };

            // Assert
            Assert.Equal("ArgumentNullException", exceptionInfo.Type);
            Assert.Equal("Argument was null", exceptionInfo.Message);
            Assert.Equal("at Method() in File.cs:line 99", exceptionInfo.StackTrace);
        }

        [Fact]
        public void ExceptionInfo_StackTrace_CanBeNull()
        {
            // Arrange & Act
            var exceptionInfo = new ExceptionInfo { Type = "Exception", Message = "Error", StackTrace = null };

            // Assert
            Assert.Null(exceptionInfo.StackTrace);
        }
    }

    public class LoggerStaticTests
    {
        [Fact]
        public void Logger_SetDevMode_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetDevMode(true));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Logger_SetDevMode_WithVariousValues_ShouldNotThrow(bool enabled)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetDevMode(enabled));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_SetLogLevel_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetLogLevel(LogLevel.Warning));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData(LogLevel.Debug)]
        [InlineData(LogLevel.Info)]
        [InlineData(LogLevel.Warning)]
        [InlineData(LogLevel.Error)]
        [InlineData(LogLevel.Fatal)]
        public void Logger_SetLogLevel_WithVariousLevels_ShouldNotThrow(LogLevel level)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetLogLevel(level));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_SetLogFormat_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetLogFormat("json"));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData("json")]
        [InlineData("text")]
        [InlineData("plaintext")]
        public void Logger_SetLogFormat_WithVariousFormats_ShouldNotThrow(string format)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetLogFormat(format));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_SetMaxFileSizeMB_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetMaxFileSizeMb(20));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(10)]
        [InlineData(100)]
        public void Logger_SetMaxFileSizeMB_WithVariousSizes_ShouldNotThrow(int mb)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetMaxFileSizeMb(mb));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_SetMaxRetainedFiles_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetMaxRetainedFiles(15));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(5)]
        [InlineData(20)]
        public void Logger_SetMaxRetainedFiles_WithVariousCounts_ShouldNotThrow(int count)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetMaxRetainedFiles(count));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_SetEnableFileLogging_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetEnableFileLogging(false));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Logger_SetEnableFileLogging_WithVariousValues_ShouldNotThrow(bool enabled)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetEnableFileLogging(enabled));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_SetEnableCompression_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetEnableCompression(true));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Logger_SetEnableCompression_WithVariousValues_ShouldNotThrow(bool enabled)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetEnableCompression(enabled));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_SetIncludeTimestamps_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetIncludeTimestamps(false));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Logger_SetIncludeTimestamps_WithVariousValues_ShouldNotThrow(bool enabled)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetIncludeTimestamps(enabled));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_SetIncludeThreadId_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetIncludeThreadId(true));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Logger_SetIncludeThreadId_WithVariousValues_ShouldNotThrow(bool enabled)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetIncludeThreadId(enabled));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_SetDateTimeFormat_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetDateTimeFormat("UTC"));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData("UTC")]
        [InlineData("LOCAL")]
        public void Logger_SetDateTimeFormat_WithVariousFormats_ShouldNotThrow(string format)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetDateTimeFormat(format));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_SetAsyncLogging_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetAsyncLogging(false));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Logger_SetAsyncLogging_WithVariousValues_ShouldNotThrow(bool enabled)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.SetAsyncLogging(enabled));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_ReloadConfig_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(Logger.ReloadConfig);
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_GetCurrentSessionId_ShouldReturnNonEmptyString()
        {
            // Act
            var sessionId = Logger.GetCurrentSessionId();

            // Assert
            Assert.NotNull(sessionId);
            Assert.NotEmpty(sessionId);
        }

        [Fact]
        public void Logger_GetCurrentLogFilePath_ShouldReturnNonEmptyString()
        {
            // Act
            var logPath = Logger.GetCurrentLogFilePath();

            // Assert
            Assert.NotNull(logPath);
            Assert.NotEmpty(logPath);
        }

        [Fact]
        public void Logger_GetCurrentLogFilePath_ShouldContainExpectedFileName()
        {
            // Act
            var logPath = Logger.GetCurrentLogFilePath();

            // Assert
            Assert.Contains("cdl.log", logPath);
        }

        [Fact]
        public void Logger_Log_WithInfoLevel_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.Log(LogLevel.Info, "Test message"));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_Log_WithErrorLevel_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.Log(LogLevel.Error, "Error message"));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_Log_WithException_ShouldNotThrow()
        {
            // Arrange
            var ex = new InvalidOperationException("Test exception");

            // Act & Assert
            var exception = Record.Exception(() => Logger.Log(LogLevel.Error, "An error occurred", ex));
            Assert.Null(exception);
        }

        [Theory]
        [InlineData(LogLevel.Debug)]
        [InlineData(LogLevel.Info)]
        [InlineData(LogLevel.Warning)]
        [InlineData(LogLevel.Error)]
        [InlineData(LogLevel.Fatal)]
        public void Logger_Log_WithVariousLogLevels_ShouldNotThrow(LogLevel level)
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.Log(level, "Test message"));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_Log_WithEmptyMessage_ShouldNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => Logger.Log(LogLevel.Info, string.Empty));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_Log_WithLongMessage_ShouldNotThrow()
        {
            // Arrange
            var longMessage = new string('A', 10000);

            // Act & Assert
            var exception = Record.Exception(() => Logger.Log(LogLevel.Info, longMessage));
            Assert.Null(exception);
        }

        [Fact]
        public void Logger_Log_WithSpecialCharactersInMessage_ShouldNotThrow()
        {
            // Arrange
            var message = "Special chars: @#$%^&*()[]{}|\\<>?/~`!";

            // Act & Assert
            var exception = Record.Exception(() => Logger.Log(LogLevel.Info, message));
            Assert.Null(exception);
        }
    }
}
