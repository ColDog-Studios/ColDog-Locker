using ColDogStudios.ColDogLocker.Infrastructure.Logging;

namespace ColDogStudios.ColDogLocker.Infrastructure.Tests.Logging
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
            Assert.Null(logEntry.SourceFile);
            Assert.Null(logEntry.LineNumber);
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
        public void LogEntry_SourceFile_CanBeSet()
        {
            // Arrange
            var logEntry = new LogEntry();
            var sourceFile = "TestFile.cs";

            // Act
            logEntry.SourceFile = sourceFile;

            // Assert
            Assert.Equal(sourceFile, logEntry.SourceFile);
        }

        [Fact]
        public void LogEntry_LineNumber_CanBeSet()
        {
            // Arrange
            var logEntry = new LogEntry();
            var lineNumber = 42;

            // Act
            logEntry.LineNumber = lineNumber;

            // Assert
            Assert.Equal(lineNumber, logEntry.LineNumber);
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
            var sourceFile = "Program.cs";
            var lineNumber = 123;
            var sessionId = "session_001";

            // Act
            var logEntry = new LogEntry
            {
                Timestamp = timestamp,
                Level = level,
                Message = message,
                SourceFile = sourceFile,
                LineNumber = lineNumber,
                SessionId = sessionId
            };

            // Assert
            Assert.Equal(timestamp, logEntry.Timestamp);
            Assert.Equal(level, logEntry.Level);
            Assert.Equal(message, logEntry.Message);
            Assert.Equal(sourceFile, logEntry.SourceFile);
            Assert.Equal(lineNumber, logEntry.LineNumber);
            Assert.Equal(sessionId, logEntry.SessionId);
        }

        [Theory]
        [InlineData("Debug")]
        [InlineData("Info")]
        [InlineData("Success")]
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
        public void LogEntry_SourceFile_CanBeNull()
        {
            // Arrange & Act
            var logEntry = new LogEntry
            {
                SourceFile = null
            };

            // Assert
            Assert.Null(logEntry.SourceFile);
        }

        [Fact]
        public void LogEntry_LineNumber_CanBeNull()
        {
            // Arrange & Act
            var logEntry = new LogEntry
            {
                LineNumber = null
            };

            // Assert
            Assert.Null(logEntry.LineNumber);
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
        public void LogLevel_ShouldHaveSuccessValue()
        {
            // Act & Assert
            Assert.Equal(2, (int)LogLevel.Success);
        }

        [Fact]
        public void LogLevel_ShouldHaveWarningValue()
        {
            // Act & Assert
            Assert.Equal(3, (int)LogLevel.Warning);
        }

        [Fact]
        public void LogLevel_ShouldHaveErrorValue()
        {
            // Act & Assert
            Assert.Equal(4, (int)LogLevel.Error);
        }

        [Fact]
        public void LogLevel_ToString_ShouldReturnCorrectName()
        {
            // Act & Assert
            Assert.Equal("Debug", LogLevel.Debug.ToString());
            Assert.Equal("Info", LogLevel.Info.ToString());
            Assert.Equal("Success", LogLevel.Success.ToString());
            Assert.Equal("Warning", LogLevel.Warning.ToString());
            Assert.Equal("Error", LogLevel.Error.ToString());
            Assert.Equal("Fatal", LogLevel.Fatal.ToString());
        }

        [Theory]
        [InlineData(LogLevel.Debug, "Debug")]
        [InlineData(LogLevel.Info, "Info")]
        [InlineData(LogLevel.Success, "Success")]
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
            Assert.Equal(6, allLevels.Length);
            Assert.Contains(LogLevel.Debug, allLevels);
            Assert.Contains(LogLevel.Info, allLevels);
            Assert.Contains(LogLevel.Success, allLevels);
            Assert.Contains(LogLevel.Warning, allLevels);
            Assert.Contains(LogLevel.Error, allLevels);
            Assert.Contains(LogLevel.Fatal, allLevels);
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

        // Logger_SetLogRetentionDays test removed (obsolete)
    }
}
