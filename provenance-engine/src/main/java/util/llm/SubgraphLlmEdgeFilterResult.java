package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
import org.jgrapht.graph.DirectedPseudograph;
import model.EntityNode;
import model.EventEdge;

/** Auditable result of attack-story-aware process-subgraph filtering. */
public final class SubgraphLlmEdgeFilterResult {
   private final DirectedPseudograph<EntityNode, EventEdge> retainedGraph;
   private final String systemPrompt;
   private final List<BatchResult> batches;
   private final List<DecisionRecord> decisions;
   private final String degradedReason;
   private final boolean enabled;
   private final int inputNodeCount;
   private final int inputEdgeCount;
   private final int subgraphCount;
   private final int batchSize;
   private final int removedIsolatedNodes;
   private final int removedDisconnectedNodes;
   private final int retainedAnchorNodes;

   SubgraphLlmEdgeFilterResult(DirectedPseudograph<EntityNode, EventEdge> retainedGraph, String systemPrompt,
      List<BatchResult> batches, List<DecisionRecord> decisions, String degradedReason, boolean enabled, int inputNodeCount,
      int inputEdgeCount, int subgraphCount, int batchSize, int removedIsolatedNodes, int removedDisconnectedNodes,
      int retainedAnchorNodes) {
      this.retainedGraph = retainedGraph;
      this.systemPrompt = systemPrompt == null ? "" : systemPrompt;
      this.batches = Collections.unmodifiableList(new ArrayList<>(batches));
      this.decisions = Collections.unmodifiableList(new ArrayList<>(decisions));
      this.degradedReason = degradedReason == null ? "" : degradedReason;
      this.enabled = enabled;
      this.inputNodeCount = inputNodeCount;
      this.inputEdgeCount = inputEdgeCount;
      this.subgraphCount = subgraphCount;
      this.batchSize = batchSize;
      this.removedIsolatedNodes = removedIsolatedNodes;
      this.removedDisconnectedNodes = removedDisconnectedNodes;
      this.retainedAnchorNodes = retainedAnchorNodes;
   }

   public DirectedPseudograph<EntityNode, EventEdge> getRetainedGraph() { return this.retainedGraph; }
   public List<BatchResult> getBatches() { return this.batches; }
   public List<DecisionRecord> getDecisions() { return this.decisions; }
   public String getDegradedReason() { return this.degradedReason; }
   public boolean isEnabled() { return this.enabled; }
   public int getInputNodeCount() { return this.inputNodeCount; }
   public int getInputEdgeCount() { return this.inputEdgeCount; }
   public int getSubgraphCount() { return this.subgraphCount; }
   public int getBatchSize() { return this.batchSize; }
   public int getRemovedIsolatedNodes() { return this.removedIsolatedNodes; }
   public int getRemovedDisconnectedNodes() { return this.removedDisconnectedNodes; }
   public int getRetainedAnchorNodes() { return this.retainedAnchorNodes; }

   public int getSuggestedDropCount() { return this.decisions.size(); }
   public int getAcceptedDropCount() {
      int count = 0;
      for (DecisionRecord decision : this.decisions) if (decision.isAccepted()) count++;
      return count;
   }
   public int getRejectedMissingEdgeCount() {
      int count = 0;
      for (DecisionRecord decision : this.decisions) if ("rejected_edge_not_present".equals(decision.getDisposition())) count++;
      return count;
   }
   public int getFailedBatchCount() {
      int count = 0;
      for (BatchResult batch : this.batches) if (!"success".equals(batch.getStatus())) count++;
      return count;
   }

   public String toSummaryText() {
      StringBuilder out = new StringBuilder();
      out.append("noise_mode=subgraph").append(System.lineSeparator())
         .append("enabled=").append(this.enabled).append(System.lineSeparator())
         .append("input_nodes=").append(this.inputNodeCount).append(System.lineSeparator())
         .append("input_edges=").append(this.inputEdgeCount).append(System.lineSeparator())
         .append("subgraphs=").append(this.subgraphCount).append(System.lineSeparator())
         .append("batch_size=").append(this.batchSize).append(System.lineSeparator())
         .append("batches=").append(this.batches.size()).append(System.lineSeparator())
         .append("suggested_drops=").append(getSuggestedDropCount()).append(System.lineSeparator())
         .append("accepted_drops=").append(getAcceptedDropCount()).append(System.lineSeparator())
         .append("rejected_edge_not_present=").append(getRejectedMissingEdgeCount()).append(System.lineSeparator())
         .append("failed_batches=").append(getFailedBatchCount()).append(System.lineSeparator())
          .append("retained_edges=").append(this.retainedGraph.edgeSet().size()).append(System.lineSeparator())
          .append("removed_isolated_nodes=").append(this.removedIsolatedNodes).append(System.lineSeparator())
          .append("removed_disconnected_nodes=").append(this.removedDisconnectedNodes).append(System.lineSeparator())
          .append("retained_anchor_nodes=").append(this.retainedAnchorNodes).append(System.lineSeparator())
         .append("degraded_reason=").append(this.degradedReason).append(System.lineSeparator());
      for (BatchResult batch : this.batches) out.append(batch.toSummaryLine()).append(System.lineSeparator());
      for (DecisionRecord decision : this.decisions) out.append(decision.toSummaryLine()).append(System.lineSeparator());
      return out.toString();
   }

   public JSONObject getQuestionJson() {
      JSONArray payload = new JSONArray();
      for (BatchResult batch : this.batches) payload.put(batch.toQuestionJson());
      return new JSONObject().put("system_prompt", this.systemPrompt).put("batches", payload);
   }

   public String getAnswersText() {
      StringBuilder out = new StringBuilder();
      for (BatchResult batch : this.batches) {
         if (out.length() > 0) out.append(System.lineSeparator()).append(System.lineSeparator());
         out.append("=== BATCH ").append(batch.getBatchIndex()).append(" ===").append(System.lineSeparator());
         out.append(batch.getRawResponse());
      }
      return out.toString();
   }

   public JSONObject getDecisionsJson() {
      JSONArray payload = new JSONArray();
      for (DecisionRecord decision : this.decisions) payload.put(decision.toJson());
      return new JSONObject().put("decisions", payload);
   }

   public static final class BatchResult {
      private final int batchIndex;
      private final List<Long> rootProcessIds;
      private final Map<Long, String> rootRoles;
      private final int ownedEdgeCount;
      private final int contextEdgeCount;
      private final String previousSummary;
      private final String updatedSummary;
      private final String userPrompt;
      private final String rawResponse;
      private final String status;
      private final int invalidLineCount;
      private final int outsideBatchIdCount;
      private final int contextOnlyIdCount;
      private final int duplicateDropCount;

      BatchResult(int batchIndex, List<Long> rootProcessIds, Map<Long, String> rootRoles, int ownedEdgeCount,
         int contextEdgeCount, String previousSummary, String updatedSummary, String userPrompt, String rawResponse, String status,
         int invalidLineCount, int outsideBatchIdCount, int contextOnlyIdCount, int duplicateDropCount) {
         this.batchIndex = batchIndex;
         this.rootProcessIds = Collections.unmodifiableList(new ArrayList<>(rootProcessIds));
         this.rootRoles = Collections.unmodifiableMap(new LinkedHashMap<>(rootRoles));
         this.ownedEdgeCount = ownedEdgeCount;
         this.contextEdgeCount = contextEdgeCount;
         this.previousSummary = previousSummary == null ? "" : previousSummary;
         this.updatedSummary = updatedSummary == null ? "" : updatedSummary;
         this.userPrompt = userPrompt == null ? "" : userPrompt;
         this.rawResponse = rawResponse == null ? "" : rawResponse;
         this.status = status == null ? "success" : status;
         this.invalidLineCount = invalidLineCount;
         this.outsideBatchIdCount = outsideBatchIdCount;
         this.contextOnlyIdCount = contextOnlyIdCount;
         this.duplicateDropCount = duplicateDropCount;
      }

      public int getBatchIndex() { return this.batchIndex; }
      public List<Long> getRootProcessIds() { return this.rootProcessIds; }
      public String getStatus() { return this.status; }
      public String getRawResponse() { return this.rawResponse; }
      String toSummaryLine() {
         return "batch=" + this.batchIndex + " roots=" + this.rootProcessIds + " roles=" + this.rootRoles
            + " owned_edges=" + this.ownedEdgeCount + " context_edges=" + this.contextEdgeCount + " status=" + this.status
            + " invalid_lines=" + this.invalidLineCount + " outside_batch_ids=" + this.outsideBatchIdCount
            + " context_only_ids=" + this.contextOnlyIdCount + " duplicate_drops=" + this.duplicateDropCount
            + " updated_summary=" + this.updatedSummary;
      }
      JSONObject toQuestionJson() {
         return new JSONObject().put("batch_index", this.batchIndex).put("root_process_ids", new JSONArray(this.rootProcessIds))
            .put("root_roles", new JSONObject(this.rootRoles)).put("owned_edge_count", this.ownedEdgeCount)
            .put("context_edge_count", this.contextEdgeCount).put("previous_summary", this.previousSummary)
            .put("user_prompt", this.userPrompt).put("status", this.status);
      }
   }

   public static final class DecisionRecord {
      private final int batchIndex;
      private final long edgeId;
      private final long ownerRootProcessId;
      private final String reason;
      private final String disposition;

      DecisionRecord(int batchIndex, long edgeId, long ownerRootProcessId, String reason, String disposition) {
         this.batchIndex = batchIndex;
         this.edgeId = edgeId;
         this.ownerRootProcessId = ownerRootProcessId;
         this.reason = reason == null ? "" : reason;
         this.disposition = disposition == null ? "accepted" : disposition;
      }
      public int getBatchIndex() { return this.batchIndex; }
      public long getEdgeId() { return this.edgeId; }
      public boolean isAccepted() { return "accepted".equals(this.disposition); }
      public String getDisposition() { return this.disposition; }
      String toSummaryLine() {
         return "decision batch=" + this.batchIndex + " edge_id=" + this.edgeId + " owner_root=" + this.ownerRootProcessId
            + " disposition=" + this.disposition + " reason=" + this.reason;
      }
      JSONObject toJson() {
         return new JSONObject().put("batch_index", this.batchIndex).put("edge_id", this.edgeId)
            .put("owner_root_process_id", this.ownerRootProcessId).put("reason", this.reason).put("disposition", this.disposition);
      }
   }
}
