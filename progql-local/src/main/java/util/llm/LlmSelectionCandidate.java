package util.llm;

import main.Main;
import model.EntityNode;
import org.json.JSONObject;

public final class LlmSelectionCandidate {
   private final int rank;
   private final int candidateRank;
   private final long entryId;
   private final String signature;
   private final double reputation;
   private final double compositeScore;
   private final String reason;
   private final EntityNode entry;

   public LlmSelectionCandidate(
      int rank,
      int candidateRank,
      EntityNode entry,
      String reason
   ) {
      if (entry == null) {
         throw new IllegalArgumentException("Selected LLM candidate entry cannot be null.");
      }

      this.rank = rank;
      this.candidateRank = candidateRank;
      this.entryId = entry.getId();
      this.signature = entry.getSignature();
      this.reputation = entry.getReputation();
      this.compositeScore = Main.getEntryCompositeScore(entry);
      this.reason = reason == null ? "" : reason;
      this.entry = entry;
   }

   public int getRank() {
      return this.rank;
   }

   public int getCandidateRank() {
      return this.candidateRank;
   }

   public long getEntryId() {
      return this.entryId;
   }

   public String getSignature() {
      return this.signature;
   }

   public double getReputation() {
      return this.reputation;
   }

   public double getCompositeScore() {
      return this.compositeScore;
   }

   public String getReason() {
      return this.reason;
   }

   public EntityNode getEntry() {
      return this.entry;
   }

   public JSONObject toJsonObject() {
      return new JSONObject()
         .put("candidate_rank", this.candidateRank)
         .put("entry_id", this.entryId)
         .put("rank", this.rank)
         .put("signature", this.signature)
         .put("composite_score", this.compositeScore)
         .put("reputation", this.reputation)
         .put("reason", this.reason);
   }
}
