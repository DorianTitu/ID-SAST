using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp;

class CSharpASTAnalyzer
{
    private static HttpListener? listener;
    
    static async Task Main(string[] args)
    {
        listener = new HttpListener();
        listener.Prefixes.Add("http://0.0.0.0:5003/");
        listener.Start();
        
        Console.WriteLine("C# AST Analyzer running on port 5003");
        Console.WriteLine("Parser: Roslyn");
        
        while (true)
        {
            HttpListenerContext context = listener.GetContext();
            await HandleRequest(context);
        }
    }
    
    static async Task HandleRequest(HttpListenerContext context)
    {
        string path = context.Request.Url.AbsolutePath;
        string method = context.Request.HttpMethod;
        
        try
        {
            if (path == "/health" && method == "GET")
            {
                var response = new
                {
                    service = "csharp-analyzer",
                    status = "ok",
                    engine = "Roslyn",
                    version = "4.8.0"
                };
                SendJsonResponse(context, 200, response);
            }
            else if (path == "/analyze" && method == "POST")
            {
                string body = await ReadRequestBody(context);
                var request = JsonSerializer.Deserialize<JsonElement>(body);
                
                string code = request.TryGetProperty("code", out var codeElem) ? codeElem.GetString() : "";
                string filename = request.TryGetProperty("filename", out var filenameElem) ? filenameElem.GetString() : "unknown.cs";
                
                if (string.IsNullOrEmpty(code))
                {
                    var error = new { error = "Code is required", file = filename, language = "csharp" };
                    SendJsonResponse(context, 400, error);
                    return;
                }
                
                try
                {
                    var tree = CSharpSyntaxTree.ParseText(code);
                    var root = tree.GetRoot();
                    
                    var response = new
                    {
                        success = true,
                        file = filename,
                        language = "csharp",
                        ast = new { kind = root.GetType().Name, content = root.ToString() },
                        error = (string)null
                    };
                    
                    SendJsonResponse(context, 200, response);
                }
                catch (Exception ex)
                {
                    var error = new { error = ex.Message, file = filename, language = "csharp" };
                    SendJsonResponse(context, 500, error);
                }
            }
            else
            {
                SendJsonResponse(context, 404, new { error = "Not Found" });
            }
        }
        catch (Exception ex)
        {
            SendJsonResponse(context, 500, new { error = ex.Message });
        }
    }
    
    static async Task<string> ReadRequestBody(HttpListenerContext context)
    {
        using (StreamReader reader = new StreamReader(context.Request.InputStream, Encoding.UTF8))
        {
            return await reader.ReadToEndAsync();
        }
    }
    
    static void SendJsonResponse(HttpListenerContext context, int statusCode, object data)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        
        string json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
        byte[] buffer = Encoding.UTF8.GetBytes(json);
        
        context.Response.ContentLength64 = buffer.Length;
        context.Response.OutputStream.Write(buffer, 0, buffer.Length);
        context.Response.OutputStream.Close();
    }
}
