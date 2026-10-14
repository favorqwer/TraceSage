package util.llm;

public class LlmRepairSelectedEdge {
   private final int rank;
   private final String missingType;
   private final String reason;

   public LlmRepairSelectedEdge(int rank, String missingType, String reason) {
      this.rank = rank;
      this.missingType = missingType == null ? "" : missingType.trim();
      this.reason = reason == null ? "" : reason.trim();
   }

   public int getRank() {
      return this.rank;
   }

   public String getMissingType() {
      return this.missingType;
   }

   public String getReason() {
      return this.reason;
   }

   public String toLine() {
      return LlmRepairCandidateEdge.formatToken(this.rank)
         + " " + this.missingType + (this.reason.isEmpty() ? "" : " " + this.reason);
   }
}
