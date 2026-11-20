namespace Becetti.Security.Core.Models;

/// <summary>
/// Result of an operation that can fail. Services return this instead of
/// throwing so the UI can always show the real error message.
/// </summary>
public class OperationResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public string? ErrorCode { get; init; }

    public static OperationResult Ok(string message = "OK") =>
        new() { Success = true, Message = message };

    public static OperationResult Fail(string message, string? errorCode = null) =>
        new() { Success = false, Message = message, ErrorCode = errorCode };
}

/// <summary>Generic operation result.</summary>
public sealed class OperationResult<T> : OperationResult
{
    public T? Value { get; init; }

    public static OperationResult<T> Ok(T value, string message = "OK") =>
        new() { Success = true, Message = message, Value = value };

    public static new OperationResult<T> Fail(string message, string? errorCode = null) =>
        new() { Success = false, Message = message, ErrorCode = errorCode };
}
