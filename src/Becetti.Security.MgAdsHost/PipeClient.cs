using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Becetti.Security.MgAdsHost
{
    /// <summary>
    /// Line-based named-pipe client. The WinUI 3 app is the server; this host
    /// connects as a client. Messages are simple, whitespace-separated tokens
    /// so neither side needs a JSON parser for control messages (ad callbacks
    /// from the SDK are JSON and are parsed with Newtonsoft before being sent).
    /// </summary>
    internal sealed class PipeClient : IDisposable
    {
        private readonly NamedPipeClientStream _pipe;
        private readonly StreamReader _reader;
        private readonly StreamWriter _writer;
        private readonly object _writeLock = new object();
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private Task _readLoop;

        public event Action<string> CommandReceived;

        public PipeClient(string pipeName)
        {
            if (string.IsNullOrWhiteSpace(pipeName))
                throw new ArgumentException("Pipe name is required.", nameof(pipeName));

            _pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut,
                PipeOptions.Asynchronous);
            _pipe.Connect(15000);

            var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            _reader = new StreamReader(_pipe, encoding);
            _writer = new StreamWriter(_pipe, encoding) { AutoFlush = true };
        }

        public void Start()
        {
            _readLoop = Task.Run(() => ReadLoopAsync(_cts.Token));
        }

        private async Task ReadLoopAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var line = await _reader.ReadLineAsync().ConfigureAwait(false);
                    if (line == null)
                        break;

                    line = line.Trim();
                    if (line.Length == 0)
                        continue;

                    var handler = CommandReceived;
                    if (handler != null)
                        handler(line);
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
        }

        public bool Send(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return true;

            try
            {
                lock (_writeLock)
                {
                    _writer.WriteLine(line);
                }
                return true;
            }
            catch (IOException) { return false; }
            catch (ObjectDisposedException) { return false; }
        }

        public void Dispose()
        {
            try { _cts.Cancel(); } catch { }
            try { _writer.Dispose(); } catch { }
            try { _reader.Dispose(); } catch { }
            try { _pipe.Dispose(); } catch { }
            _cts.Dispose();
        }
    }
}
