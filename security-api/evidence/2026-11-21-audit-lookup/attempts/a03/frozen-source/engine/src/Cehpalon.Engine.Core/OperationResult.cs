namespace Cehpalon.Engine.Core;

/// <summary>An intentional business failure. Messages must be safe for the adapter's intended audience.</summary>
public sealed class OperationError
{
    public OperationError(string code, string message)
    {
        Code = OperationId.RequireValid(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        if (message.Length > 4096) throw new ArgumentException("Error messages are limited to 4096 characters.", nameof(message));
        Message = message;
    }
    public string Code { get; }
    public string Message { get; }
}

/// <summary>A valid-by-construction result. A successful nullable response may intentionally contain null.</summary>
public sealed class OperationResult<T>
{
    private readonly T? value;
    private readonly OperationError? error;
    private OperationResult(bool isSuccess, T? value, OperationError? error)
        => (IsSuccess, this.value, this.error) = (isSuccess, value, error);

    public bool IsSuccess { get; }
    public T Value => IsSuccess ? value! : throw new InvalidOperationException("A failed result has no response value.");
    public OperationError Error => !IsSuccess ? error! : throw new InvalidOperationException("A successful result has no error.");
    public static OperationResult<T> Success(T value) => new(true, value, null);
    public static OperationResult<T> Failure(OperationError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new(false, default, error);
    }
}
