package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

public class LlmRepairResult {
   private final DirectedPseudograph<EntityNode, EventEdge> finalGraph;
   private final List<LlmRepairRoundResult> rounds;
   private final List<AgentCycle> agentCycles;
   private final List<String> rejectedEdges;
   private final String stopReason;
   private final String attackKnowledgeVersion;

   public LlmRepairResult(DirectedPseudograph<EntityNode, EventEdge> finalGraph, List<LlmRepairRoundResult> rounds) {
      this(finalGraph, rounds, Collections.<AgentCycle>emptyList(), "", "");
   }

   public LlmRepairResult(
      DirectedPseudograph<EntityNode, EventEdge> finalGraph,
      List<LlmRepairRoundResult> rounds,
      List<AgentCycle> agentCycles,
      String stopReason,
      String attackKnowledgeVersion
   ) {
      this.finalGraph = finalGraph;
      this.rounds = rounds == null ? Collections.emptyList() : rounds;
      this.agentCycles = agentCycles == null ? Collections.emptyList() : new ArrayList<>(agentCycles);
      this.stopReason = stopReason == null ? "" : stopReason;
      this.attackKnowledgeVersion = attackKnowledgeVersion == null ? "" : attackKnowledgeVersion;
      List<String> rejected = new ArrayList<>();
      for (AgentCycle cycle : this.agentCycles) rejected.addAll(cycle.getRejectedEdges());
      this.rejectedEdges = Collections.unmodifiableList(rejected);
   }

   public DirectedPseudograph<EntityNode, EventEdge> getFinalGraph() {
      return this.finalGraph;
   }

   public List<LlmRepairRoundResult> getRounds() {
      return this.rounds;
   }

   public List<AgentCycle> getAgentCycles() { return this.agentCycles; }
   public List<String> getRejectedEdges() { return this.rejectedEdges; }
   public String getStopReason() { return this.stopReason; }
   public String getAttackKnowledgeVersion() { return this.attackKnowledgeVersion; }

   public int getAddedEdgeCount() {
      int count = 0;
      for (LlmRepairRoundResult round : this.rounds) {
         count += round.getAddedEdges().size();
      }
      return count;
   }

   public static final class AgentCycle {
      private final int cycle;
      private final AgentPhase assessment;
      private final AgentPhase selection;
      private final List<String> rejectedEdges;
      private final int candidateCount;
      private final int addedEdgeCount;
      private final String stopReason;
      private final int baseEdgeCount;
      private final int candidatePoolCount;
      private final List<Integer> proposedCandidateRanks;
      private final int penalizedCandidateCount;
      private final int unselectedCandidateCount;
      private final int hardRejectedCandidateCount;
      private final Map<String, Integer> candidateCountsByGap;
      private final Map<String, String> gapDiagnostics;

      public AgentCycle(int cycle, AgentPhase assessment, AgentPhase selection,
         List<String> rejectedEdges, int candidateCount, int addedEdgeCount) {
         this(cycle, assessment, selection, rejectedEdges, candidateCount, addedEdgeCount, "");
      }

      public AgentCycle(int cycle, AgentPhase assessment, AgentPhase selection,
         List<String> rejectedEdges, int candidateCount, int addedEdgeCount, String stopReason) {
         this(cycle, assessment, selection, rejectedEdges, candidateCount, addedEdgeCount, stopReason,
            0, 0, Collections.<Integer>emptyList());
      }

      public AgentCycle(int cycle, AgentPhase assessment, AgentPhase selection,
         List<String> rejectedEdges, int candidateCount, int addedEdgeCount, String stopReason,
         int baseEdgeCount, int candidatePoolCount, List<Integer> proposedCandidateRanks) {
         this(cycle, assessment, selection, rejectedEdges, candidateCount, addedEdgeCount, stopReason,
            baseEdgeCount, candidatePoolCount, proposedCandidateRanks, 0, 0, 0);
      }

      public AgentCycle(int cycle, AgentPhase assessment, AgentPhase selection,
         List<String> rejectedEdges, int candidateCount, int addedEdgeCount, String stopReason,
         int baseEdgeCount, int candidatePoolCount, List<Integer> proposedCandidateRanks,
         int penalizedCandidateCount, int unselectedCandidateCount, int hardRejectedCandidateCount) {
         this(cycle, assessment, selection, rejectedEdges, candidateCount, addedEdgeCount, stopReason,
            baseEdgeCount, candidatePoolCount, proposedCandidateRanks, penalizedCandidateCount, unselectedCandidateCount,
            hardRejectedCandidateCount, Collections.<String, Integer>emptyMap(), Collections.<String, String>emptyMap());
      }

      public AgentCycle(int cycle, AgentPhase assessment, AgentPhase selection,
         List<String> rejectedEdges, int candidateCount, int addedEdgeCount, String stopReason,
         int baseEdgeCount, int candidatePoolCount, List<Integer> proposedCandidateRanks,
         int penalizedCandidateCount, int unselectedCandidateCount, int hardRejectedCandidateCount,
         Map<String, Integer> candidateCountsByGap, Map<String, String> gapDiagnostics) {
         this.cycle = cycle;
         this.assessment = assessment == null ? AgentPhase.empty() : assessment;
         this.selection = selection == null ? AgentPhase.empty() : selection;
         this.rejectedEdges = rejectedEdges == null ? Collections.emptyList() : new ArrayList<>(rejectedEdges);
         this.candidateCount = candidateCount;
         this.addedEdgeCount = addedEdgeCount;
         this.stopReason = stopReason == null ? "" : stopReason;
         this.baseEdgeCount = Math.max(0, baseEdgeCount);
         this.candidatePoolCount = Math.max(0, candidatePoolCount);
         this.proposedCandidateRanks = proposedCandidateRanks == null ? Collections.<Integer>emptyList() : new ArrayList<>(proposedCandidateRanks);
         this.penalizedCandidateCount = Math.max(0, penalizedCandidateCount);
         this.unselectedCandidateCount = Math.max(0, unselectedCandidateCount);
         this.hardRejectedCandidateCount = Math.max(0, hardRejectedCandidateCount);
         this.candidateCountsByGap = Collections.unmodifiableMap(new LinkedHashMap<>(
            candidateCountsByGap == null ? Collections.<String, Integer>emptyMap() : candidateCountsByGap
         ));
         this.gapDiagnostics = Collections.unmodifiableMap(new LinkedHashMap<>(
            gapDiagnostics == null ? Collections.<String, String>emptyMap() : gapDiagnostics
         ));
      }
      public int getCycle() { return cycle; }
      public AgentPhase getAssessment() { return assessment; }
      public AgentPhase getSelection() { return selection; }
      public List<String> getRejectedEdges() { return rejectedEdges; }
      public int getCandidateCount() { return candidateCount; }
      public int getAddedEdgeCount() { return addedEdgeCount; }
      public String getStopReason() { return stopReason; }
      public int getBaseEdgeCount() { return baseEdgeCount; }
      public int getCandidatePoolCount() { return candidatePoolCount; }
      public List<Integer> getProposedCandidateRanks() { return proposedCandidateRanks; }
      public int getPenalizedCandidateCount() { return penalizedCandidateCount; }
      public int getUnselectedCandidateCount() { return unselectedCandidateCount; }
      public int getHardRejectedCandidateCount() { return hardRejectedCandidateCount; }
      public Map<String, Integer> getCandidateCountsByGap() { return candidateCountsByGap; }
      public Map<String, String> getGapDiagnostics() { return gapDiagnostics; }
   }

   public static final class AgentPhase {
      private final String prompt;
      private final String response;
      private final String finishReason;
      private final int validLineCount;
      private final int ignoredLineCount;
      private final String correctionPrompt;
      private final String correctionResponse;
      private final String correctionFinishReason;
      private final int correctionValidLineCount;
      private final int correctionIgnoredLineCount;

      public AgentPhase(String prompt, String response, String finishReason, int validLineCount, int ignoredLineCount) {
         this(prompt, response, finishReason, validLineCount, ignoredLineCount, "", "", "", 0, 0);
      }

      private AgentPhase(String prompt, String response, String finishReason, int validLineCount, int ignoredLineCount,
         String correctionPrompt, String correctionResponse, String correctionFinishReason,
         int correctionValidLineCount, int correctionIgnoredLineCount) {
         this.prompt = prompt == null ? "" : prompt;
         this.response = response == null ? "" : response;
         this.finishReason = finishReason == null ? "" : finishReason;
         this.validLineCount = Math.max(0, validLineCount);
         this.ignoredLineCount = Math.max(0, ignoredLineCount);
         this.correctionPrompt = correctionPrompt == null ? "" : correctionPrompt;
         this.correctionResponse = correctionResponse == null ? "" : correctionResponse;
         this.correctionFinishReason = correctionFinishReason == null ? "" : correctionFinishReason;
         this.correctionValidLineCount = Math.max(0, correctionValidLineCount);
         this.correctionIgnoredLineCount = Math.max(0, correctionIgnoredLineCount);
      }

      public static AgentPhase empty() { return new AgentPhase("", "", "", 0, 0); }
      public AgentPhase withCorrection(String prompt, String response, String finishReason, int validLines, int ignoredLines) {
         return new AgentPhase(this.prompt, this.response, this.finishReason, this.validLineCount, this.ignoredLineCount,
            prompt, response, finishReason, validLines, ignoredLines);
      }
      public String getPrompt() { return prompt; }
      public String getResponse() { return response; }
      public String getFinishReason() { return finishReason; }
      public int getValidLineCount() { return validLineCount; }
      public int getIgnoredLineCount() { return ignoredLineCount; }
      public boolean isCorrectionAttempted() { return !this.correctionPrompt.isEmpty() || !this.correctionResponse.isEmpty(); }
      public String getCorrectionPrompt() { return correctionPrompt; }
      public String getCorrectionResponse() { return correctionResponse; }
      public String getCorrectionFinishReason() { return correctionFinishReason; }
      public int getCorrectionValidLineCount() { return correctionValidLineCount; }
      public int getCorrectionIgnoredLineCount() { return correctionIgnoredLineCount; }
   }

   public static final class LlmRepairRoundResult {
      private final int round;
      private final String anchorQuestion;
      private final String anchorAnswer;
      private final String edgeQuestion;
      private final String edgeAnswer;
      private final List<String> missingTypes;
      private final String summary;
      private final String problemDetails;
      private final List<LlmRepairNode> anchors;
      private final List<LlmRepairCandidateEdge> candidates;
      private final List<LlmRepairSelectedEdge> selectedEdges;
      private final List<EventEdge> addedEdges;
      private final DirectedPseudograph<EntityNode, EventEdge> graphAfterRound;

      public LlmRepairRoundResult(
         int round,
         String anchorQuestion,
         String anchorAnswer,
         String edgeQuestion,
         String edgeAnswer,
         List<String> missingTypes,
         String summary,
         String problemDetails,
         List<LlmRepairNode> anchors,
         List<LlmRepairCandidateEdge> candidates,
         List<LlmRepairSelectedEdge> selectedEdges,
         List<EventEdge> addedEdges,
         DirectedPseudograph<EntityNode, EventEdge> graphAfterRound
      ) {
         this.round = round;
         this.anchorQuestion = blankIfNull(anchorQuestion);
         this.anchorAnswer = blankIfNull(anchorAnswer);
         this.edgeQuestion = blankIfNull(edgeQuestion);
         this.edgeAnswer = blankIfNull(edgeAnswer);
         this.missingTypes = missingTypes == null ? Collections.emptyList() : new ArrayList<>(missingTypes);
         this.summary = blankIfNull(summary);
         this.problemDetails = blankIfNull(problemDetails);
         this.anchors = anchors == null ? Collections.emptyList() : new ArrayList<>(anchors);
         this.candidates = candidates == null ? Collections.emptyList() : new ArrayList<>(candidates);
         this.selectedEdges = selectedEdges == null ? Collections.emptyList() : new ArrayList<>(selectedEdges);
         this.addedEdges = addedEdges == null ? Collections.emptyList() : new ArrayList<>(addedEdges);
         this.graphAfterRound = graphAfterRound;
      }

      public int getRound() {
         return this.round;
      }

      public String getAnchorQuestion() {
         return this.anchorQuestion;
      }

      public String getAnchorAnswer() {
         return this.anchorAnswer;
      }

      public String getEdgeQuestion() {
         return this.edgeQuestion;
      }

      public String getEdgeAnswer() {
         return this.edgeAnswer;
      }

      public List<String> getMissingTypes() {
         return this.missingTypes;
      }

      public String getSummary() {
         return this.summary;
      }

      public String getProblemDetails() {
         return this.problemDetails;
      }

      public List<LlmRepairNode> getAnchors() {
         return this.anchors;
      }

      public List<LlmRepairCandidateEdge> getCandidates() {
         return this.candidates;
      }

      public List<LlmRepairSelectedEdge> getSelectedEdges() {
         return this.selectedEdges;
      }

      public List<EventEdge> getAddedEdges() {
         return this.addedEdges;
      }

      public DirectedPseudograph<EntityNode, EventEdge> getGraphAfterRound() {
         return this.graphAfterRound;
      }

      private static String blankIfNull(String value) {
         return value == null ? "" : value;
      }
   }
}
