package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class RepairDecision {
   private final List<Selection> selections;
   private final String rawText;
   private final LlmSemanticRepairLineParser.ParseDiagnostics diagnostics;

   RepairDecision(List<Selection> selections, String rawText, LlmSemanticRepairLineParser.ParseDiagnostics diagnostics) {
      this.selections = Collections.unmodifiableList(new ArrayList<>(selections));
      this.rawText = rawText == null ? "" : rawText;
      this.diagnostics = diagnostics == null ? new LlmSemanticRepairLineParser.ParseDiagnostics(0, 0) : diagnostics;
   }

   public static RepairDecision parse(String response, GraphAssessment assessment, int maxRank, int maxSelected) {
      return LlmSemanticRepairLineParser.parseSelection(response, assessment, maxRank, maxSelected);
   }

   public List<Selection> getSelections() { return selections; }
   public String getRawText() { return rawText; }
   public int getValidLineCount() { return diagnostics.getValidLines(); }
   public int getIgnoredLineCount() { return diagnostics.getIgnoredLines(); }
   public int getSelectedRankCount() {
      int count = 0;
      for (Selection selection : selections) count += selection.getRanks().size();
      return count;
   }

   public static final class Selection {
      private final String gapId; private final List<Integer> ranks; private final String unresolvedReason;
      Selection(String gapId, List<Integer> ranks, String unresolvedReason) {
         this.gapId = gapId;
         this.ranks = Collections.unmodifiableList(new ArrayList<>(ranks));
         this.unresolvedReason = unresolvedReason == null ? "" : unresolvedReason;
      }
      public String getGapId() { return gapId; }
      public List<Integer> getRanks() { return ranks; }
      public String getUnresolvedReason() { return unresolvedReason; }
   }
}
