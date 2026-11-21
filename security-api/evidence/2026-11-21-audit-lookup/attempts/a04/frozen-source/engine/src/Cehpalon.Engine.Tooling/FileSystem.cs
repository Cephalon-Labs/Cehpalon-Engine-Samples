namespace Cehpalon.Engine.Tooling;

// A bounded seam for tests, not an alternate path/authorization mechanism.
internal interface IToolingFileSystem
{
    void WriteAllBytes(string path, byte[] bytes);
    void MoveDirectory(string source, string destination);
}

internal sealed class PhysicalToolingFileSystem : IToolingFileSystem
{
    public void WriteAllBytes(string path, byte[] bytes)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        file.Write(bytes);
        file.Flush(flushToDisk: true);
    }

    public void MoveDirectory(string source, string destination) => Directory.Move(source, destination);
}
