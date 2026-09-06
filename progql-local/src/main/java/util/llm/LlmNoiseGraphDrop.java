package util.llm;

import org.json.JSONObject;

/** An edge explicitly reported by the LLM as noise to remove. */
public class LlmNoiseGraphDrop {
   private final long edgeId;
   private final int edgeRank;
   private final String reason;

   public LlmNoiseGraphDrop(long edgeId, int edgeRank, String reason) {
      this.edgeId = edgeId;
      this.edgeRank = edgeRank;
      this.reason = reason == null ? "" : reason;
   }

   public long getEdgeId() {
      return this.edgeId;
   }

   public int getEdgeRank() {
      return this.edgeRank;
   }

   public String getReason() {
      return this.reason;
   }

   public JSONObject toJsonObject() {
      return new JSONObject()
         .put("edge_id", this.edgeId)
         .put("edge_rank", this.edgeRank)
         .put("reason", this.reason);
   }
}
