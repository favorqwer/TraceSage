package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

public class LlmNoiseGraphResult {
   private final LlmNoiseGraphQuestionRecord questionRecord;
   private final List<LlmNoiseGraphEdge> graphEdges;
   private final List<LlmNoiseGraphDrop> droppedEdges;
   private final String summary;
   private final String rawResponseText;
   private final int statusCode;
   private final boolean fallbackUsed;
   private final boolean llmInvoked;
   private final List<LlmNoiseGraphBatchResult> batchResults;
   private final LlmConfig.NoiseMode noiseMode;
   private final int llmRequestCount;
   private final Integer effectiveSliceSize;
   private final Integer effectivePartitionSize;
   private final int partitionCount;
   private final int successfulRequestCount;
   private final int fallbackPartitionCount;

   public LlmNoiseGraphResult(
      LlmNoiseGraphQuestionRecord questionRecord,
      List<LlmNoiseGraphEdge> graphEdges,
      List<LlmNoiseGraphDrop> droppedEdges,
      String summary,
      String rawResponseText,
      int statusCode,
      boolean fallbackUsed,
      boolean llmInvoked
   ) {
      this(
         questionRecord,
         graphEdges,
         droppedEdges,
         summary,
         rawResponseText,
         statusCode,
         fallbackUsed,
         llmInvoked,
         new ArrayList<LlmNoiseGraphBatchResult>(),
         null,
         llmInvoked ? 1 : 0,
         null,
         null,
         0,
         0,
         0
      );
   }

   public LlmNoiseGraphResult(
      LlmNoiseGraphQuestionRecord questionRecord,
      List<LlmNoiseGraphEdge> graphEdges,
      List<LlmNoiseGraphDrop> droppedEdges,
      String summary,
      String rawResponseText,
      int statusCode,
      boolean fallbackUsed,
      boolean llmInvoked,
      List<LlmNoiseGraphBatchResult> batchResults,
      LlmConfig.NoiseMode noiseMode,
      int llmRequestCount
   ) {
      this(
         questionRecord,
         graphEdges,
         droppedEdges,
         summary,
         rawResponseText,
         statusCode,
         fallbackUsed,
         llmInvoked,
         batchResults,
         noiseMode,
         llmRequestCount,
         null,
         null,
         0,
         0,
         0
      );
   }

   public LlmNoiseGraphResult(
      LlmNoiseGraphQuestionRecord questionRecord,
      List<LlmNoiseGraphEdge> graphEdges,
      List<LlmNoiseGraphDrop> droppedEdges,
      String summary,
      String rawResponseText,
      int statusCode,
      boolean fallbackUsed,
      boolean llmInvoked,
      List<LlmNoiseGraphBatchResult> batchResults,
      LlmConfig.NoiseMode noiseMode,
      int llmRequestCount,
      Integer effectiveSliceSize,
      Integer effectivePartitionSize,
      int partitionCount,
      int successfulRequestCount,
      int fallbackPartitionCount
   ) {
      this.questionRecord = questionRecord;
      this.graphEdges = Collections.unmodifiableList(new ArrayList<>(graphEdges));
      this.droppedEdges = Collections.unmodifiableList(new ArrayList<>(droppedEdges));
      this.summary = summary == null ? "" : summary;
      this.rawResponseText = rawResponseText == null ? "" : rawResponseText;
      this.statusCode = statusCode;
      this.fallbackUsed = fallbackUsed;
      this.llmInvoked = llmInvoked;
      this.batchResults = Collections.unmodifiableList(new ArrayList<>(batchResults));
      this.noiseMode = noiseMode;
      this.llmRequestCount = Math.max(0, llmRequestCount);
      this.effectiveSliceSize = effectiveSliceSize;
      this.effectivePartitionSize = effectivePartitionSize;
      this.partitionCount = Math.max(0, partitionCount);
      this.successfulRequestCount = Math.max(0, successfulRequestCount);
      this.fallbackPartitionCount = Math.max(0, fallbackPartitionCount);
   }

   public JSONObject getQuestionRecordJson() {
      return this.questionRecord.toJsonObject();
   }

   public QuestionRecordView getQuestionRecord() {
      return new QuestionRecordView(this.questionRecord);
   }

   public List<LlmNoiseGraphDrop> getDroppedEdges() {
      return this.droppedEdges;
   }

   public boolean isFallbackUsed() {
      return this.fallbackUsed;
   }

   public List<LlmNoiseGraphBatchResult> getBatchResults() {
      return this.batchResults;
   }

   public String getNoiseMode() {
      return this.noiseMode == null ? "not_invoked" : this.noiseMode.getConfigValue();
   }

   public int getInputEdgeCount() {
      return this.graphEdges.size();
   }

   public int getLlmRequestCount() {
      return this.llmRequestCount;
   }

   public Integer getEffectivePartitionSize() {
      return this.effectivePartitionSize;
   }

   public int getPartitionCount() {
      return this.partitionCount;
   }

   public int getSuccessfulRequestCount() {
      return this.successfulRequestCount;
   }

   public int getFallbackPartitionCount() {
      return this.fallbackPartitionCount;
   }

   public int getDroppedEdgeCount() {
      return this.droppedEdges.size();
   }

   public int getRetainedEdgeCount() {
      return Math.max(0, getInputEdgeCount() - getDroppedEdgeCount());
   }

   public Set<Integer> getDroppedEdgeRanks() {
      Set<Integer> ranks = new LinkedHashSet<>();
      for (LlmNoiseGraphDrop drop : this.droppedEdges) ranks.add(drop.getEdgeRank());
      return ranks;
   }

   public JSONObject toJsonObject() {
      JSONArray droppedEdgeArray = new JSONArray();
      JSONArray batchArray = new JSONArray();

      for (LlmNoiseGraphDrop drop : this.droppedEdges) droppedEdgeArray.put(drop.toJsonObject());

      for (LlmNoiseGraphBatchResult batchResult : this.batchResults) {
         batchArray.put(batchResult.toJsonObject());
      }

      return new JSONObject()
         .put("summary", this.summary)
         .put("http_status", this.statusCode)
         .put("fallback_used", this.fallbackUsed)
         .put("llm_invoked", this.llmInvoked)
         .put("noise_mode", getNoiseMode())
         .put("effective_slice_size", this.effectiveSliceSize == null ? JSONObject.NULL : this.effectiveSliceSize)
         .put("effective_partition_size", this.effectivePartitionSize == null ? JSONObject.NULL : this.effectivePartitionSize)
         .put("partition_count", this.partitionCount)
         .put("successful_request_count", this.successfulRequestCount)
         .put("fallback_partition_count", this.fallbackPartitionCount)
         .put("input_edge_count", getInputEdgeCount())
         .put("llm_request_count", getLlmRequestCount())
         .put("dropped_edge_count", getDroppedEdgeCount())
         .put("retained_edge_count", getRetainedEdgeCount())
         .put("dropped_edges", droppedEdgeArray)
         .put("raw_response_text", this.rawResponseText)
         .put("batch_results", batchArray);
   }

   public static final class QuestionRecordView {
      private final JSONObject json;

      private QuestionRecordView(LlmNoiseGraphQuestionRecord questionRecord) {
         this.json = questionRecord.toJsonObject();
      }

      public JSONObject toJsonObject() {
         return this.json;
      }
   }
}

class LlmNoiseGraphBatchPromptRecord {
   private final int batchIndex;
   private final int totalBatches;
   private final String userPrompt;

   LlmNoiseGraphBatchPromptRecord(int batchIndex, int totalBatches, String userPrompt) {
      this.batchIndex = batchIndex;
      this.totalBatches = totalBatches;
      this.userPrompt = userPrompt == null ? "" : userPrompt;
   }

   JSONObject toJsonObject() {
      return new JSONObject()
         .put("batch_index", this.batchIndex)
         .put("total_batches", this.totalBatches)
         .put("user_prompt", this.userPrompt);
   }
}

class LlmNoiseGraphQuestionRecord extends LlmPromptRecord {
   private final List<LlmNoiseGraphBatchPromptRecord> batchPrompts;

   LlmNoiseGraphQuestionRecord(String provider, String endpoint, String model, String systemPrompt, String userPrompt) {
      this(provider, endpoint, model, systemPrompt, userPrompt, new ArrayList<LlmNoiseGraphBatchPromptRecord>());
   }

   LlmNoiseGraphQuestionRecord(
      String provider,
      String endpoint,
      String model,
      String systemPrompt,
      String userPrompt,
      List<LlmNoiseGraphBatchPromptRecord> batchPrompts
   ) {
      super(provider, endpoint, model, systemPrompt, userPrompt);
      this.batchPrompts = Collections.unmodifiableList(new ArrayList<>(batchPrompts));
   }

   @Override
   JSONObject toJsonObject() {
      JSONArray batchPromptArray = new JSONArray();
      for (LlmNoiseGraphBatchPromptRecord batchPrompt : this.batchPrompts) {
         batchPromptArray.put(batchPrompt.toJsonObject());
      }

      JSONObject json = new JSONObject()
         .put("provider", getProvider())
         .put("endpoint", getEndpoint())
         .put("model", getModel())
         .put("system_prompt", getSystemPrompt());
      if (!this.batchPrompts.isEmpty()) {
         return json.put("batch_prompts", batchPromptArray);
      }
      return json.put("user_prompt", getUserPrompt());
   }
}

class LlmNoiseGraphBatchResult {
   private final int batchIndex;
   private final int startEdgeRank;
   private final int endEdgeRank;
   private final String previousSummary;
   private final String updatedSummary;
   private final String rawResponseText;
   private final int statusCode;
   private final boolean fallbackUsed;
   private final List<LlmNoiseGraphDrop> droppedEdges;

   LlmNoiseGraphBatchResult(
      int batchIndex,
      int startEdgeRank,
      int endEdgeRank,
      String previousSummary,
      String updatedSummary,
      String rawResponseText,
      int statusCode,
      boolean fallbackUsed,
      List<LlmNoiseGraphDrop> droppedEdges
   ) {
      this.batchIndex = batchIndex;
      this.startEdgeRank = startEdgeRank;
      this.endEdgeRank = endEdgeRank;
      this.previousSummary = previousSummary == null ? "" : previousSummary;
      this.updatedSummary = updatedSummary == null ? "" : updatedSummary;
      this.rawResponseText = rawResponseText == null ? "" : rawResponseText;
      this.statusCode = statusCode;
      this.fallbackUsed = fallbackUsed;
      this.droppedEdges = Collections.unmodifiableList(new ArrayList<>(droppedEdges));
   }

   int getBatchIndex() {
      return this.batchIndex;
   }

   String getUpdatedSummary() {
      return this.updatedSummary;
   }

   boolean isFallbackUsed() {
      return this.fallbackUsed;
   }

   List<LlmNoiseGraphDrop> getDroppedEdges() {
      return this.droppedEdges;
   }

   int getDroppedEdgeCount() {
      return this.droppedEdges.size();
   }

   JSONObject toJsonObject() {
      JSONArray droppedEdgeArray = new JSONArray();
      for (LlmNoiseGraphDrop drop : this.droppedEdges) droppedEdgeArray.put(drop.toJsonObject());

      return new JSONObject()
         .put("batch_index", this.batchIndex)
         .put("start_edge_rank", this.startEdgeRank)
         .put("end_edge_rank", this.endEdgeRank)
         .put("previous_summary", this.previousSummary)
         .put("updated_summary", this.updatedSummary)
         .put("http_status", this.statusCode)
         .put("fallback_used", this.fallbackUsed)
         .put("dropped_edge_count", getDroppedEdgeCount())
         .put("retained_edge_count", Math.max(0, this.endEdgeRank - this.startEdgeRank + 1 - getDroppedEdgeCount()))
         .put("dropped_edges", droppedEdgeArray)
         .put("raw_response_text", this.rawResponseText);
   }
}
