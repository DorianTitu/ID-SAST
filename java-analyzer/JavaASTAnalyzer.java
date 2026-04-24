import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import com.google.gson.*;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class JavaASTAnalyzer {
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private static final JavaParser parser = new JavaParser();

    public static void main(String[] args) throws IOException {
        int port = 5002;
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);

        // Health endpoint
        server.createContext("/health", new HealthHandler());
        
        // Analyze endpoint
        server.createContext("/analyze", new AnalyzeHandler());

        server.setExecutor(null);
        server.start();

        System.out.println("Java AST Analyzer running on port " + port);
        System.out.println("Parser: JavaParser");
    }

    static class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            JsonObject response = new JsonObject();
            response.addProperty("service", "java-analyzer");
            response.addProperty("status", "ok");
            response.addProperty("engine", "JavaParser");
            response.addProperty("version", "3.25.0");

            String json = gson.toJson(response);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, json.getBytes().length);
            OutputStream os = exchange.getResponseBody();
            os.write(json.getBytes());
            os.close();
        }
    }

    static class AnalyzeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                String body = readRequestBody(exchange);
                JsonObject request = JsonParser.parseString(body).getAsJsonObject();

                String code = request.has("code") ? request.get("code").getAsString() : "";
                String filename = request.has("filename") ? request.get("filename").getAsString() : "unknown.java";

                if (code.isEmpty()) {
                    sendResponse(exchange, 400, createErrorResponse("Code is required", filename));
                    return;
                }

                try {
                    var parseResult = parser.parse(code);
                    if (parseResult.isSuccessful()) {
                        CompilationUnit cu = parseResult.getResult().get();
                        JsonObject response = new JsonObject();
                        response.addProperty("success", true);
                        response.addProperty("file", filename);
                        response.addProperty("language", "java");
                        response.add("ast", JsonParser.parseString(gson.toJson(cu)));
                        response.add("error", JsonNull.INSTANCE);

                        sendResponse(exchange, 200, response.toString());
                    } else {
                        sendResponse(exchange, 400, createErrorResponse("Parse error", filename));
                    }
                } catch (Exception e) {
                    sendResponse(exchange, 500, createErrorResponse(e.getMessage(), filename));
                }
            } else {
                sendResponse(exchange, 405, "{}");
            }
        }

        private String readRequestBody(HttpExchange exchange) throws IOException {
            InputStream is = exchange.getRequestBody();
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            reader.close();
            return sb.toString();
        }

        private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, response.getBytes().length);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }

        private String createErrorResponse(String error, String filename) {
            JsonObject response = new JsonObject();
            response.addProperty("error", error);
            response.addProperty("file", filename);
            response.addProperty("language", "java");
            return response.toString();
        }
    }
}
