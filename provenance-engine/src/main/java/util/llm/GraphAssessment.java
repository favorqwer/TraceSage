package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

public final class GraphAssessment {
   private final List<ObservedTactic> observedTactics;
   private final List<StorySegment> storySegments;
   private final List<Gap> gaps;
   private final String summary;
   private final String rawText;
   private final LlmSemanticRepairLineParser.ParseDiagnostics diagnostics;

   GraphAssessment(List<ObservedTactic> observedTactics, List<StorySegment> storySegments, List<Gap> gaps,
      String summary, String rawText, LlmSemanticRepairLineParser.ParseDiagnostics diagnostics) {
      this.observedTactics = Collections.unmodifiableList(new ArrayList<>(observedTactics));
      this.storySegments = Collections.unmodifiableList(new ArrayList<>(storySegments));
      this.gaps = Collections.unmodifiableList(new ArrayList<>(gaps));
      this.summary = summary == null ? "" : summary;
      this.rawText = rawText == null ? "" : rawText;
      this.diagnostics = diagnostics == null ? new LlmSemanticRepairLineParser.ParseDiagnostics(0, 0) : diagnostics;
   }

   public static GraphAssessment parse(String response, AttackTacticKnowledge knowledge,
      DirectedPseudograph<EntityNode, EventEdge> universe, int maxGaps) {
      return LlmSemanticRepairLineParser.parseAssessment(response, knowledge, universe, maxGaps);
   }

   public List<ObservedTactic> getObservedTactics() { return observedTactics; }
   public List<StorySegment> getStorySegments() { return storySegments; }
   public List<Gap> getGaps() { return gaps; }
   public String getSummary() { return summary; }
   public String getRawText() { return rawText; }
   public int getValidLineCount() { return diagnostics.getValidLines(); }
   public int getIgnoredLineCount() { return diagnostics.getIgnoredLines(); }

   public String toProtocolText() {
      StringBuilder builder = new StringBuilder();
      if (!summary.isEmpty()) builder.append("SUMMARY ").append(summary).append('\n');
      for (ObservedTactic tactic : observedTactics) {
         builder.append("TACTIC ").append(tactic.getTacticId()).append(' ').append(joinIds(tactic.getEvidenceEdgeIds())).append('\n');
      }
      for (StorySegment segment : storySegments) {
         builder.append("SEGMENT ").append(segment.getFromTactic()).append(' ').append(segment.getToTactic())
            .append(' ').append(joinIds(segment.getEvidenceEdgeIds())).append('\n');
      }
      for (Gap gap : gaps) {
         builder.append("GAP ").append(gap.getGapId()).append(' ').append(gap.getBeforeTactic()).append(' ')
            .append(gap.getAfterTactic()).append(' ').append(gap.getPriority()).append(' ')
            .append(joinIds(gap.getAnchorNodeIds())).append(" :: ").append(gap.getDescription()).append('\n');
      }
      builder.append("END");
      return builder.toString();
   }

   public String gapSignature() { return gaps.toString(); }

   private static String joinIds(List<Long> values) {
      if (values == null || values.isEmpty()) return "-";
      StringBuilder builder = new StringBuilder();
      for (Long value : values) {
         if (builder.length() > 0) builder.append(',');
         builder.append(value);
      }
      return builder.toString();
   }

   public static final class ObservedTactic {
      private final String tacticId; private final List<Long> evidenceEdgeIds;
      ObservedTactic(String tacticId, List<Long> evidenceEdgeIds) { this.tacticId = tacticId; this.evidenceEdgeIds = Collections.unmodifiableList(new ArrayList<>(evidenceEdgeIds)); }
      public String getTacticId() { return tacticId; }
      public List<Long> getEvidenceEdgeIds() { return evidenceEdgeIds; }
   }
   public static final class StorySegment {
      private final String fromTactic; private final String toTactic; private final List<Long> evidenceEdgeIds;
      StorySegment(String fromTactic, String toTactic, List<Long> evidenceEdgeIds) { this.fromTactic = fromTactic; this.toTactic = toTactic; this.evidenceEdgeIds = Collections.unmodifiableList(new ArrayList<>(evidenceEdgeIds)); }
      public String getFromTactic() { return fromTactic; }
      public String getToTactic() { return toTactic; }
      public List<Long> getEvidenceEdgeIds() { return evidenceEdgeIds; }
   }
   public static final class Gap {
      private final String gapId; private final String beforeTactic; private final String afterTactic;
      private final String description; private final List<Long> anchorNodeIds; private final double priority;
      Gap(String gapId, String beforeTactic, String afterTactic, String description, List<Long> anchorNodeIds, double priority) {
         this.gapId = gapId; this.beforeTactic = beforeTactic; this.afterTactic = afterTactic;
         this.description = description == null ? "" : description;
         this.anchorNodeIds = Collections.unmodifiableList(new ArrayList<>(anchorNodeIds)); this.priority = priority;
      }
      public String getGapId() { return gapId; }
      public String getBeforeTactic() { return beforeTactic; }
      public String getAfterTactic() { return afterTactic; }
      public String getDescription() { return description; }
      public List<Long> getAnchorNodeIds() { return anchorNodeIds; }
      public double getPriority() { return priority; }
      @Override public String toString() { return gapId + ":" + beforeTactic + "->" + afterTactic + ":" + anchorNodeIds; }
   }
}
