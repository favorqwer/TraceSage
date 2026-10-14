package util.llm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.json.JSONArray;
import org.json.JSONObject;

public class LlmConnectivityProbe {
   private static final int NVIDIA_MAX_ATTEMPTS = 4;
   private static final String EMPTY_MESSAGE_ERROR_PREFIX = "LLM response message content is empty:";

   public LlmChatResult chatCompletion(LlmConfig config, String systemPrompt, String userPrompt) {
      IOException lastIoException = null;
      IllegalStateException lastStateException = null;

      for (int attempt = 1; attempt <= NVIDIA_MAX_ATTEMPTS; attempt++) {
         try {
            HttpResponse finalResponse = executeSingleAttempt(config, systemPrompt, userPrompt);
            if (finalResponse.statusCode < 200 || finalResponse.statusCode >= 300) {
               IllegalStateException failure = new IllegalStateException(
                  "LLM request failed with HTTP " + finalResponse.statusCode + ": " + abbreviate(finalResponse.body)
               );
               if (!isRetriableFailure(finalResponse.statusCode, attempt)) {
                  throw failure;
               }

               lastStateException = failure;
               System.out.println(
                  "LLM request attempt " + attempt + " failed with HTTP " + finalResponse.statusCode + "; retrying the same request."
               );
            } else {
               try {
                  return buildChatResult(finalResponse.statusCode, finalResponse.body, extractRequestId(finalResponse));
               } catch (IllegalStateException ex) {
                  if (!isRetriableEmptyResponse(ex, attempt)) {
                     throw ex;
                  }

                  lastStateException = ex;
                  System.out.println("LLM request attempt " + attempt + " returned an empty completion; retrying the same request.");
               }
            }
         } catch (IOException ex) {
            lastIoException = ex;
            if (attempt >= NVIDIA_MAX_ATTEMPTS) {
               throw new IllegalStateException("LLM request failed after retries: " + ex.getMessage(), ex);
            }

            System.out.println("LLM request attempt " + attempt + " failed with I/O error: " + ex.getMessage() + "; retrying.");
         }

         sleepQuietly(1000L);
      }

      if (lastStateException != null) {
         throw lastStateException;
      }

      if (lastIoException != null) {
         throw new IllegalStateException("LLM request failed after retries: " + lastIoException.getMessage(), lastIoException);
      }

      throw new IllegalStateException("LLM request failed after retries for an unknown reason.");
   }

   private HttpResponse executeSingleAttempt(LlmConfig config, String systemPrompt, String userPrompt) throws IOException {
      HttpResponse initialResponse = executeRequest(config, new URL(config.getEndpoint()), buildPayload(config, systemPrompt, userPrompt));
      if (initialResponse.statusCode != 202) {
         return initialResponse;
      }

      String requestId = extractRequestId(initialResponse);
      if (requestId == null || requestId.isEmpty()) {
         throw new IllegalStateException("LLM request returned HTTP 202 without a request id.");
      }

      return pollStatus(config, requestId);
   }

   private LlmChatResult buildChatResult(int statusCode, String responseBody, String requestId) {
      validateResponse(responseBody);
      return new LlmChatResult(statusCode, responseBody, extractMessageText(responseBody), requestId, extractFinishReason(responseBody));
   }

   private HttpResponse pollStatus(LlmConfig config, String requestId) throws IOException {
      URL statusUrl = new URL(buildStatusEndpoint(config.getEndpoint(), requestId));
      long deadline = System.currentTimeMillis() + Math.max(config.getReadTimeoutMs(), 1000);
      HttpResponse response = null;

      while (System.currentTimeMillis() <= deadline) {
         response = executeGet(config, statusUrl);
         if (response.statusCode == 202) {
            sleepQuietly(1000L);
            continue;
         }

         if (response.statusCode < 200 || response.statusCode >= 300) {
            throw new IllegalStateException(
               "LLM status polling failed with HTTP " + response.statusCode + ": " + abbreviate(response.body)
            );
         }

         return response;
      }

      throw new IllegalStateException("LLM status polling timed out for request id: " + requestId);
   }

   private HttpResponse executeRequest(LlmConfig config, URL url, JSONObject payload) throws IOException {
      HttpURLConnection connection = (HttpURLConnection)url.openConnection();

      try {
         connection.setRequestMethod("POST");
         connection.setConnectTimeout(config.getConnectTimeoutMs());
         connection.setReadTimeout(config.getReadTimeoutMs());
         connection.setDoOutput(true);
         connection.setRequestProperty("Authorization", "Bearer " + config.getApiKey());
         connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
         connection.setRequestProperty("Accept", "application/json");
         byte[] body = payload.toString().getBytes(StandardCharsets.UTF_8);
         connection.setFixedLengthStreamingMode(body.length);
         try (OutputStream outputStream = connection.getOutputStream()) {
            outputStream.write(body);
         }

         int statusCode = connection.getResponseCode();
         String responseBody = readBody(statusCode >= 400 ? connection.getErrorStream() : connection.getInputStream());
         return new HttpResponse(statusCode, responseBody, connection.getHeaderField("NVCF-REQID"), connection.getHeaderField("X-Request-Id"));
      } finally {
         connection.disconnect();
      }
   }

   private HttpResponse executeGet(LlmConfig config, URL url) throws IOException {
      HttpURLConnection connection = (HttpURLConnection)url.openConnection();

      try {
         connection.setRequestMethod("GET");
         connection.setConnectTimeout(config.getConnectTimeoutMs());
         connection.setReadTimeout(config.getReadTimeoutMs());
         connection.setRequestProperty("Authorization", "Bearer " + config.getApiKey());
         connection.setRequestProperty("Accept", "application/json");
         int statusCode = connection.getResponseCode();
         String responseBody = readBody(statusCode >= 400 ? connection.getErrorStream() : connection.getInputStream());
         return new HttpResponse(statusCode, responseBody, connection.getHeaderField("NVCF-REQID"), connection.getHeaderField("X-Request-Id"));
      } finally {
         connection.disconnect();
      }
   }

   static JSONObject buildPayload(LlmConfig config, String systemPrompt, String userPrompt) {
      JSONArray messages = new JSONArray();
      messages.put(new JSONObject().put("role", "user").put("content", mergePrompts(systemPrompt, userPrompt)));
      return new JSONObject()
         .put("messages", messages)
         .put("model", config.getModel())
         .put("temperature", config.getTemperature());
   }

   /** Executes exactly one request attempt. Process-subgraph edge filtering uses this to avoid hidden retries per batch. */
   public LlmChatResult chatCompletionSingleAttempt(LlmConfig config, String systemPrompt, String userPrompt) {
      try {
         HttpResponse response = executeSingleAttempt(config, systemPrompt, userPrompt);
         if (response.statusCode < 200 || response.statusCode >= 300) {
            throw new IllegalStateException("LLM request failed with HTTP " + response.statusCode + ": " + abbreviate(response.body));
         }
         return buildChatResult(response.statusCode, response.body, extractRequestId(response));
      } catch (IOException ex) {
         throw new IllegalStateException("LLM request failed: " + ex.getMessage(), ex);
      }
   }

   private static String mergePrompts(String systemPrompt, String userPrompt) {
      String normalizedSystem = systemPrompt == null ? "" : systemPrompt.trim();
      String normalizedUser = userPrompt == null ? "" : userPrompt.trim();
      if (normalizedSystem.isEmpty()) {
         return normalizedUser;
      }

      if (normalizedUser.isEmpty()) {
         return normalizedSystem;
      }

      return normalizedSystem + System.lineSeparator() + System.lineSeparator() + normalizedUser;
   }

   private static boolean isRetriableFailure(int statusCode, int attempt) {
      if (attempt >= NVIDIA_MAX_ATTEMPTS) {
         return false;
      }

      return statusCode >= 500;
   }

   private static boolean isRetriableEmptyResponse(IllegalStateException ex, int attempt) {
      return attempt < NVIDIA_MAX_ATTEMPTS
         && ex != null
         && ex.getMessage() != null
         && ex.getMessage().startsWith(EMPTY_MESSAGE_ERROR_PREFIX);
   }

   private static String buildStatusEndpoint(String endpoint, String requestId) {
      int v1Index = endpoint.indexOf("/v1/");
      if (v1Index < 0) {
         throw new IllegalStateException("Unable to derive NVIDIA status endpoint from: " + endpoint);
      }

      String prefix = endpoint.substring(0, v1Index);
      return prefix + "/v1/status/" + requestId;
   }

   private static String extractRequestId(HttpResponse response) {
      if (response == null) {
         return null;
      }

      if (response.primaryRequestId != null && !response.primaryRequestId.trim().isEmpty()) {
         return response.primaryRequestId.trim();
      }

      if (response.secondaryRequestId != null && !response.secondaryRequestId.trim().isEmpty()) {
         return response.secondaryRequestId.trim();
      }

      if (response.body == null || response.body.trim().isEmpty()) {
         return null;
      }

      try {
         JSONObject json = new JSONObject(response.body);
         if (json.has("requestId")) {
            return json.get("requestId").toString();
         }

         if (json.has("id")) {
            return json.get("id").toString();
         }
      } catch (RuntimeException ignored) {
      }

      return null;
   }

   private static String readBody(InputStream inputStream) throws IOException {
      if (inputStream == null) {
         return "";
      }

      try (InputStream is = inputStream; ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
         byte[] buffer = new byte[4096];

         int read;
         while ((read = is.read(buffer)) != -1) {
            outputStream.write(buffer, 0, read);
         }

         return new String(outputStream.toByteArray(), StandardCharsets.UTF_8);
      }
   }

   private static void validateResponse(String responseBody) {
      JSONObject json = new JSONObject(responseBody);
      if (json.has("choices") && json.getJSONArray("choices").length() > 0) {
         return;
      }

      throw new IllegalStateException("LLM returned an unexpected payload: " + abbreviate(responseBody));
   }

   static String extractMessageText(String responseBody) {
      JSONObject json = new JSONObject(responseBody);
      JSONObject firstChoice = json.getJSONArray("choices").getJSONObject(0);
      JSONObject message = firstChoice.optJSONObject("message");
      if (message == null) {
         throw new IllegalStateException("LLM response is missing choices[0].message: " + abbreviate(responseBody));
      }

      String text = extractTextField(message.opt("content"));
      if (!text.isEmpty()) {
         return text;
      }

      text = extractTextField(message.opt("reasoning_content"));
      if (!text.isEmpty()) {
         return text;
      }

      throw new IllegalStateException(EMPTY_MESSAGE_ERROR_PREFIX + " " + abbreviate(responseBody));
   }

   static String extractFinishReason(String responseBody) {
      JSONObject json = new JSONObject(responseBody);
      JSONObject firstChoice = json.getJSONArray("choices").getJSONObject(0);
      Object value = firstChoice.opt("finish_reason");
      return value == null || JSONObject.NULL.equals(value) ? "" : value.toString().trim();
   }

   private static String extractTextField(Object content) {
      if (content == null || JSONObject.NULL.equals(content)) {
         return "";
      }

      if (content instanceof JSONArray) {
         StringBuilder builder = new StringBuilder();
         JSONArray array = (JSONArray)content;
         for (int i = 0; i < array.length(); i++) {
            Object item = array.get(i);
            if (item instanceof JSONObject) {
               JSONObject obj = (JSONObject)item;
               if ("text".equalsIgnoreCase(obj.optString("type")) || obj.has("text")) {
                  if (builder.length() > 0) {
                     builder.append(System.lineSeparator());
                  }

                  builder.append(obj.optString("text"));
               }
            } else if (item != null) {
               if (builder.length() > 0) {
                  builder.append(System.lineSeparator());
               }

               builder.append(item.toString());
            }
         }

         return builder.toString().trim();
      }

      return content.toString().trim();
   }

   public static String extractJsonObjectText(String text) {
      if (text == null) {
         throw new IllegalStateException("LLM returned empty text.");
      }

      String trimmed = text.trim();
      if (trimmed.startsWith("```")) {
         int firstNewline = trimmed.indexOf('\n');
         int lastFence = trimmed.lastIndexOf("```");
         if (firstNewline >= 0 && lastFence > firstNewline) {
            trimmed = trimmed.substring(firstNewline + 1, lastFence).trim();
         }
      }

      int start = trimmed.indexOf('{');
      int end = trimmed.lastIndexOf('}');
      if (start < 0 || end < start) {
         throw new IllegalStateException("LLM response did not contain a JSON object: " + abbreviate(trimmed));
      }

      return trimmed.substring(start, end + 1);
   }

   private static String abbreviate(String input) {
      if (input == null) {
         return "";
      }

      String normalized = input.replaceAll("\\s+", " ").trim();
      return normalized.length() <= 240 ? normalized : normalized.substring(0, 240) + "...";
   }

   private static void sleepQuietly(long millis) {
      try {
         Thread.sleep(millis);
      } catch (InterruptedException ex) {
         Thread.currentThread().interrupt();
         throw new IllegalStateException("Interrupted while polling LLM status.", ex);
      }
   }

   public static class LlmChatResult {
      private final int statusCode;
      private final String responseBody;
      private final String messageText;
      private final String requestId;
      private final String finishReason;

      public LlmChatResult(int statusCode, String responseBody, String messageText, String requestId, String finishReason) {
         this.statusCode = statusCode;
         this.responseBody = responseBody;
         this.messageText = messageText;
         this.requestId = requestId;
         this.finishReason = finishReason == null ? "" : finishReason;
      }

      public int getStatusCode() {
         return this.statusCode;
      }

      public String getResponseBody() {
         return this.responseBody;
      }

      public String getMessageText() {
         return this.messageText;
      }

      public String getRequestId() {
         return this.requestId;
      }

      public String getFinishReason() {
         return this.finishReason;
      }
   }

   private static class HttpResponse {
      private final int statusCode;
      private final String body;
      private final String primaryRequestId;
      private final String secondaryRequestId;

      private HttpResponse(int statusCode, String body, String primaryRequestId, String secondaryRequestId) {
         this.statusCode = statusCode;
         this.body = body;
         this.primaryRequestId = primaryRequestId;
         this.secondaryRequestId = secondaryRequestId;
      }
   }
}
