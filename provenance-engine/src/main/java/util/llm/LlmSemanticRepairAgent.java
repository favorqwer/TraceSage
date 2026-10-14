package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

/** Stateful, graph-bounded ATT&CK semantic repair agent. */
public final class LlmSemanticRepairAgent {
   private final LlmConnectivityProbe connectivityProbe;
   private final AttackTacticKnowledge tacticKnowledge;
   private final LlmRepairHardConstraintVerifier verifier;
   private final LlmGapCandidateRetriever candidateRetriever;

   public LlmSemanticRepairAgent() {
      this(new LlmConnectivityProbe(), AttackTacticKnowledge.loadDefault());
   }

   public LlmSemanticRepairAgent(LlmConnectivityProbe connectivityProbe, AttackTacticKnowledge tacticKnowledge) {
      this.connectivityProbe = connectivityProbe;
      this.tacticKnowledge = tacticKnowledge;
      this.verifier = new LlmRepairHardConstraintVerifier();
      this.candidateRetriever = new LlmGapCandidateRetriever();
   }

   public LlmRepairResult repair(RepairInput input) {
      if (input == null || input.getBaseGraph() == null) {
         return new LlmRepairResult(new DirectedPseudograph(EventEdge.class), Collections.<LlmRepairResult.LlmRepairRoundResult>emptyList(),
            Collections.<LlmRepairResult.AgentCycle>emptyList(), "invalid_input", tacticKnowledge.getVersion());
      }
      LlmConfig config = LlmConfig.load();
      DirectedPseudograph<EntityNode, EventEdge> current = copyGraph(input.getBaseGraph());
      List<LlmRepairResult.LlmRepairRoundResult> rounds = new ArrayList<>();
      List<LlmRepairResult.AgentCycle> cycles = new ArrayList<>();
      if (!config.isRepairAgentEnabled()) {
         System.out.println("LLM semantic repair agent skipped: disabled");
         return new LlmRepairResult(current, rounds, cycles, "disabled", tacticKnowledge.getVersion());
      }

      DirectedPseudograph<EntityNode, EventEdge> candidateSource = candidatePoolWithoutConfirmedEdges(input.getCandidatePool(), current);
      int initialCandidatePoolEdgeCount = candidateSource.edgeSet().size();
      if (config.isPrefilterEnabled()) {
         LlmEdgePrefilter.GraphPrefilterResult prefiltered = new LlmEdgePrefilter().filterGraph(candidateSource);
         candidateSource = prefiltered.getKeepGraph();
         System.out.println("LLM repair agent prefilter summary: " + LlmEdgePrefilter.summarize(prefiltered));
      }
      System.out.println(
         "LLM semantic repair agent started: confirmed_edges=" + current.edgeSet().size()
            + ", candidate_pool_edges=" + initialCandidatePoolEdgeCount
            + ", filtered_candidate_edges=" + candidateSource.edgeSet().size()
            + ", max_cycles=" + Math.max(0, config.getRepairAgentMaxCycles())
      );

      String stopReason = "max_cycles";
      Map<String, Integer> unselectedDisplayCounts = new LinkedHashMap<>();
      Set<String> hardRejectedEdgeKeys = new LinkedHashSet<>();
      int maxCycles = Math.max(0, config.getRepairAgentMaxCycles());
      for (int cycle = 1; cycle <= maxCycles; cycle++) {
          System.out.println("LLM semantic repair cycle " + cycle + "/" + maxCycles + ": requesting assessment");
          int baseEdgeCount = current.edgeSet().size();
         LlmRepairResult.AgentPhase assessmentPhase = LlmRepairResult.AgentPhase.empty();
         LlmRepairResult.AgentPhase selectionPhase = LlmRepairResult.AgentPhase.empty();
         String cycleStopReason = "";
         List<String> rejected = new ArrayList<>();
         List<LlmRepairCandidateEdge> candidates = new ArrayList<>();
         List<LlmRepairSelectedEdge> selected = new ArrayList<>();
         List<EventEdge> added = new ArrayList<>();
         LlmGapCandidateRetriever.RetrievalResult retrieval = LlmGapCandidateRetriever.RetrievalResult.empty();
         int penalizedCandidateCount = 0;
         int unselectedCandidateCount = 0;
         GraphAssessment assessment;
         String assessmentPrompt = buildAssessmentPrompt(input, current, config);
         try {
            LlmConnectivityProbe.LlmChatResult chatResult = chat(config, assessmentSystemPrompt(), assessmentPrompt);
            assessment = GraphAssessment.parse(chatResult.getMessageText(), tacticKnowledge, current, config.getRepairAgentMaxGaps());
            assessmentPhase = phase(assessmentPrompt, chatResult, assessment.getValidLineCount(), assessment.getIgnoredLineCount());
          } catch (RuntimeException ex) {
            stopReason = "assessment_failed: " + describe(ex);
            cycleStopReason = stopReason;
            assessmentPhase = failedPhase(assessmentPrompt, ex);
            System.out.println("LLM semantic repair cycle " + cycle + ": assessment failed: " + describe(ex));
            cycles.add(new LlmRepairResult.AgentCycle(cycle, assessmentPhase, selectionPhase, rejected, 0, 0, cycleStopReason,
               baseEdgeCount, candidateSource.edgeSet().size(), Collections.<Integer>emptyList()));
            break;
         }

          if (assessment.getValidLineCount() == 0) {
            stopReason = "assessment_no_valid_lines";
            cycleStopReason = stopReason;
            cycles.add(new LlmRepairResult.AgentCycle(cycle, assessmentPhase, selectionPhase, rejected, 0, 0, cycleStopReason,
               baseEdgeCount, candidateSource.edgeSet().size(), Collections.<Integer>emptyList()));
            rounds.add(emptyRound(cycle, assessmentPhase, assessment, current));
            System.out.println("LLM semantic repair cycle " + cycle + ": assessment produced no valid lines; stopping");
            break;
          }
          if (assessment.getGaps().isEmpty()) {
            stopReason = "no_gaps";
            cycleStopReason = stopReason;
            cycles.add(new LlmRepairResult.AgentCycle(cycle, assessmentPhase, selectionPhase, rejected, 0, 0, cycleStopReason,
               baseEdgeCount, candidateSource.edgeSet().size(), Collections.<Integer>emptyList()));
            rounds.add(emptyRound(cycle, assessmentPhase, assessment, current));
            System.out.println("LLM semantic repair cycle " + cycle + ": no GAPs; stopping");
            break;
          }
          System.out.println(
             "LLM semantic repair cycle " + cycle + ": assessment parsed valid_lines="
                + assessment.getValidLineCount() + ", ignored_lines=" + assessment.getIgnoredLineCount()
                + ", gaps=" + formatGapIds(assessment)
          );

         List<LlmRepairNode> anchors = anchorsForAssessment(assessment, current);
         retrieval = candidateRetriever.retrieve(
            assessment,
            current,
            candidateSource,
            config.getRepairAgentMaxCandidateEdges(),
            config.getRepairAgentGapRetrievalMaxAnchorHops(),
            unselectedDisplayCounts,
            hardRejectedEdgeKeys
         );
         candidates = retrieval.getCandidates();
         penalizedCandidateCount = countPenalizedCandidates(
            candidates, unselectedDisplayCounts, config.getRepairAgentUnselectedCandidatePenalty()
         );
          if (candidates.isEmpty()) {
            stopReason = "gap_candidate_pool_exhausted";
            cycleStopReason = stopReason;
            cycles.add(new LlmRepairResult.AgentCycle(cycle, assessmentPhase, selectionPhase, rejected, 0, 0, cycleStopReason,
               baseEdgeCount, candidateSource.edgeSet().size(), Collections.<Integer>emptyList(),
               0, 0, hardRejectedEdgeKeys.size(), retrieval.getCandidateCountsByGap(), retrieval.getDiagnosticsByGap()));
            rounds.add(round(cycle, assessmentPhase, selectionPhase, assessment, anchors, candidates, selected, added, current));
            System.out.println("LLM semantic repair cycle " + cycle + ": no GAP-local candidate edges; stopping");
            break;
          }
          System.out.println(
             "LLM semantic repair cycle " + cycle + ": candidate_edges=" + candidates.size()
                + ", penalized_candidates=" + penalizedCandidateCount
                + ", hard_rejected_candidates=" + hardRejectedEdgeKeys.size()
                + ", gap_candidate_counts=" + retrieval.getCandidateCountsByGap()
          );

          RepairDecision decision;
          String selectionPrompt = buildSelectionPrompt(assessment, candidates, retrieval, config);
          System.out.println("LLM semantic repair cycle " + cycle + ": requesting selection");
          try {
            LlmConnectivityProbe.LlmChatResult chatResult = chat(config, selectionSystemPrompt(), selectionPrompt);
            decision = RepairDecision.parse(chatResult.getMessageText(), assessment, candidates.size(), config.getRepairAgentMaxSelectedEdgesPerCycle());
            selectionPhase = phase(selectionPrompt, chatResult, decision.getValidLineCount(), decision.getIgnoredLineCount());
         } catch (RuntimeException ex) {
            stopReason = "selection_failed: " + describe(ex);
            cycleStopReason = stopReason;
            selectionPhase = failedPhase(selectionPrompt, ex);
            System.out.println("LLM semantic repair cycle " + cycle + ": selection failed: " + describe(ex));
            cycles.add(new LlmRepairResult.AgentCycle(cycle, assessmentPhase, selectionPhase, rejected, candidates.size(), 0, cycleStopReason,
               baseEdgeCount, candidateSource.edgeSet().size(), Collections.<Integer>emptyList()));
            rounds.add(round(cycle, assessmentPhase, selectionPhase, assessment, anchors, candidates, selected, added, current));
            break;
          }
          System.out.println(
             "LLM semantic repair cycle " + cycle + ": selection parsed valid_lines="
                + decision.getValidLineCount() + ", ignored_lines=" + decision.getIgnoredLineCount()
                + ", proposed=" + formatCandidateTokens(decision)
          );
          if (needsSelectionCorrection(decision)) {
             String correctionPrompt = buildSelectionCorrectionPrompt(selectionPrompt);
             System.out.println("LLM semantic repair cycle " + cycle + ": correction request 1/1 because no valid candidate token was selected");
             try {
                LlmConnectivityProbe.LlmChatResult correctionResult = chat(config, selectionCorrectionSystemPrompt(), correctionPrompt);
                RepairDecision correctedDecision = RepairDecision.parse(
                   correctionResult.getMessageText(), assessment, candidates.size(), config.getRepairAgentMaxSelectedEdgesPerCycle()
                );
                selectionPhase = selectionPhase.withCorrection(
                   correctionPrompt,
                   correctionResult.getMessageText(),
                   correctionResult.getFinishReason(),
                   correctedDecision.getValidLineCount(),
                   correctedDecision.getIgnoredLineCount()
                );
                decision = correctedDecision;
                System.out.println(
                   "LLM semantic repair cycle " + cycle + ": correction parsed valid_lines="
                      + decision.getValidLineCount() + ", ignored_lines=" + decision.getIgnoredLineCount()
                      + ", proposed=" + formatCandidateTokens(decision)
                );
             } catch (RuntimeException ex) {
                stopReason = "selection_correction_failed: " + describe(ex);
                cycleStopReason = stopReason;
                selectionPhase = selectionPhase.withCorrection(correctionPrompt, "ERROR " + describe(ex), "", 0, 0);
                System.out.println("LLM semantic repair cycle " + cycle + ": correction failed: " + describe(ex));
                cycles.add(new LlmRepairResult.AgentCycle(cycle, assessmentPhase, selectionPhase, rejected, candidates.size(), 0, cycleStopReason,
                   baseEdgeCount, candidateSource.edgeSet().size(), Collections.<Integer>emptyList()));
                rounds.add(round(cycle, assessmentPhase, selectionPhase, assessment, anchors, candidates, selected, added, current));
                break;
             }
          }
          if (decision.getSelectedRankCount() == 0 && decision.getValidLineCount() == 0) {
             stopReason = selectionPhase.isCorrectionAttempted() ? "selection_no_valid_lines_after_correction" : "selection_no_valid_lines";
             cycleStopReason = stopReason;
            cycles.add(new LlmRepairResult.AgentCycle(cycle, assessmentPhase, selectionPhase, rejected, candidates.size(), 0, cycleStopReason,
               baseEdgeCount, candidateSource.edgeSet().size(), Collections.<Integer>emptyList()));
             rounds.add(round(cycle, assessmentPhase, selectionPhase, assessment, anchors, candidates, selected, added, current));
             System.out.println("LLM semantic repair cycle " + cycle + ": no candidates selected; stopping");
             break;
          }

         Map<Integer, LlmRepairCandidateEdge> candidateByRank = new LinkedHashMap<>();
         for (LlmRepairCandidateEdge candidate : candidates) candidateByRank.put(candidate.getRank(), candidate);
          Set<Integer> selectedRanks = new LinkedHashSet<>();
         Set<String> selectedCandidateEdgeKeys = new LinkedHashSet<>();
         for (RepairDecision.Selection selection : decision.getSelections()) {
            for (Integer rank : selection.getRanks()) {
               if (rank == null || !selectedRanks.add(rank)) continue;
               LlmRepairCandidateEdge candidate = candidateByRank.get(rank);
               if (candidate == null) continue;
               if (!candidate.getGapIds().isEmpty() && !candidate.getGapIds().contains(selection.getGapId())) {
                  rejected.add("candidate=" + LlmRepairCandidateEdge.formatToken(rank) + ", gap=" + selection.getGapId()
                     + ", reasons=[candidate_not_retrieved_for_gap]");
                  continue;
               }
               String candidateEdgeKey = LlmRepairCandidateEdge.edgeKey(candidate.getEdge());
               selectedCandidateEdgeKeys.add(candidateEdgeKey);
                LlmRepairHardConstraintVerifier.ValidationResult validation = verifier.validate(
                   candidate.getEdge(), current, candidateSource, selected.size()
               );
               if (!validation.isAccepted()) {
                   rejected.add("candidate=" + LlmRepairCandidateEdge.formatToken(rank) + ", gap=" + selection.getGapId() + ", reasons=" + validation.getReasons());
                  hardRejectedEdgeKeys.add(candidateEdgeKey);
                  continue;
               }
                if (!containsEdgeKey(added, candidate.getEdge())) {
                   EventEdge edge = candidate.getEdge();
                   if (!current.containsVertex(edge.getSource())) current.addVertex(edge.getSource());
                   if (!current.containsVertex(edge.getSink())) current.addVertex(edge.getSink());
                   current.addEdge(edge.getSource(), edge.getSink(), edge);
                   selected.add(new LlmRepairSelectedEdge(rank, selection.getGapId(), "Selected by ATT&CK gap " + selection.getGapId()));
                   added.add(edge);
                }
            }
         }
         unselectedCandidateCount = recordUnselectedCandidates(candidates, selectedCandidateEdgeKeys, unselectedDisplayCounts);

          if (added.isEmpty() && !hasUnseenGapCandidate(
             candidateSource, current, retrieval.getEligibleEdgeKeys(), hardRejectedEdgeKeys, unselectedDisplayCounts
          )) {
             stopReason = "gap_candidate_pool_exhausted";
             cycleStopReason = stopReason;
          } else if (added.isEmpty()) {
             System.out.println("LLM semantic repair cycle " + cycle + ": no candidate selected; advancing candidate window");
          }

          System.out.println(
             "LLM semantic repair cycle " + cycle + ": accepted=" + formatCandidateTokens(selected)
                + ", rejected=" + formatRejected(rejected) + ", added_edges=" + added.size()
          );

         rounds.add(round(cycle, assessmentPhase, selectionPhase, assessment, anchors, candidates, selected, added, current));
         if (cycleStopReason.isEmpty()) {
            if (cycle == maxCycles) {
               stopReason = "max_cycles";
               cycleStopReason = stopReason;
            } else {
               cycleStopReason = "continue";
            }
         }
           cycles.add(new LlmRepairResult.AgentCycle(
             cycle, assessmentPhase, selectionPhase, rejected, candidates.size(), added.size(), cycleStopReason,
             baseEdgeCount, candidateSource.edgeSet().size(), selectedRanks(selected),
             penalizedCandidateCount, unselectedCandidateCount, hardRejectedEdgeKeys.size(),
             retrieval.getCandidateCountsByGap(), retrieval.getDiagnosticsByGap()
           ));
           System.out.println("LLM semantic repair cycle " + cycle + ": " + cycleStopReason);
           if (!"continue".equals(cycleStopReason) || stopReason.endsWith("_no_valid_lines")) break;
      }
      System.out.println(
         "LLM semantic repair agent finished: stop_reason=" + stopReason
            + ", cycles=" + cycles.size() + ", added_edges=" + countAddedEdges(rounds)
            + ", final_edges=" + current.edgeSet().size()
      );
      return new LlmRepairResult(current, rounds, cycles, stopReason, tacticKnowledge.getVersion());
   }

   private LlmConnectivityProbe.LlmChatResult chat(LlmConfig config, String system, String user) {
      return connectivityProbe.chatCompletion(config, system, user);
   }

   private String assessmentSystemPrompt() {
      return "You are an ATT&CK-aware provenance graph analyst. Use only supplied node and edge ids. Return only the required fixed line protocol: SUMMARY <text>; TACTIC <tactic_id> <edge_id_csv|->; SEGMENT <from_tactic> <to_tactic> <edge_id_csv|->; GAP <gap_id> <before_tactic> <after_tactic> <priority_0_to_1> <anchor_node_id_csv|-> :: <text>; END. Every record must be one line. Do not output JSON, markdown, bullets, or other prose.";
   }

   private String selectionSystemPrompt() {
      return "You are a constrained provenance repair planner. Select only candidate tokens supplied in the prompt. A valid candidate token has the exact form C001, C002, and so on; node ids, edge ids, event ids, and bare numbers are invalid selectors. Return only fixed lines: SELECT <gap_id> <candidate_token> :: <reason>; UNRESOLVED <gap_id> :: <reason>; END. Every record must be one line. Do not output JSON, markdown, bullets, or other prose.";
   }

   private String selectionCorrectionSystemPrompt() {
      return "You are correcting an invalid provenance repair selection response. Return only SELECT <gap_id> <candidate_token> :: <reason>, UNRESOLVED <gap_id> :: <reason>, and END. Valid selectors have the exact form C001, C002, and so on. Never output node ids, edge ids, event ids, or bare numbers.";
   }

   private String buildAssessmentPrompt(RepairInput input, DirectedPseudograph<EntityNode, EventEdge> current,
      LlmConfig config) {
      StringBuilder builder = new StringBuilder();
      builder.append("ATT&CK knowledge:\n").append(tacticKnowledge.toPromptText()).append("\n\n");
      builder.append("Output format:\nSUMMARY <one-line attack story>\nTACTIC <tactic_id> <edge_id_csv|->\nSEGMENT <from_tactic> <to_tactic> <edge_id_csv|->\nGAP <gap_id> <before_tactic> <after_tactic> <priority_0_to_1> <anchor_node_id_csv|-> :: <description>\nEND\n");
      builder.append("Only ids present in the graphs are valid. Keep at most ")
         .append(config.getRepairAgentMaxGaps())
         .append(" GAP lines and at most 4 edge ids per TACTIC or SEGMENT line. Inspect sensitive data-source reads, downloaded-artifact writes, file-to-process inputs, process-to-file outputs, and control-flow bridges. Do not output protocol-external text.\n\n");
      appendContext(builder, input.getContext());
      builder.append("CURRENT_CONFIRMED_GRAPH\n").append(serializeGraph(current));
      return builder.toString();
   }

   private String buildSelectionPrompt(GraphAssessment assessment, List<LlmRepairCandidateEdge> candidates,
      LlmGapCandidateRetriever.RetrievalResult retrieval, LlmConfig config) {
      StringBuilder builder = new StringBuilder();
      builder.append("ASSESSMENT\n").append(assessment.toProtocolText()).append("\n\n");
      builder.append("Output format:\nSELECT <gap_id> <candidate_token> :: <short reason>\nUNRESOLVED <gap_id> :: <short reason>\nEND\n");
      builder.append("Select at most ").append(config.getRepairAgentMaxSelectedEdgesPerCycle()).append(" total candidate tokens. Select a token only for a GAP listed in GAP_CANDIDATE_INDEX. Candidate edges are not current graph facts. Use only the exact C-prefixed candidate tokens printed below. Node ids, provenance edge ids, event ids, and bare numbers are invalid selectors. Do not output protocol-external text.\nGAP_CANDIDATE_INDEX\n");
      for (GraphAssessment.Gap gap : assessment.getGaps()) {
         List<Integer> ranks = retrieval.getRanksByGap().get(gap.getGapId());
         builder.append(gap.getGapId()).append(" candidates=").append(formatCandidateRanks(ranks));
         String diagnostic = retrieval.getDiagnosticsByGap().get(gap.getGapId());
         if (diagnostic != null && !diagnostic.isEmpty()) builder.append(" diagnostic=").append(diagnostic);
         builder.append("\n");
      }
      builder.append("\nCANDIDATE_DETAILS\n");
      for (LlmRepairCandidateEdge candidate : candidates) builder.append(candidate.toLine()).append("\n\n");
      return builder.toString();
   }

   private String buildSelectionCorrectionPrompt(String selectionPrompt) {
      return selectionPrompt
         + "\nCORRECTION_REQUIRED\n"
         + "The previous selection used no valid candidate token. Reissue the complete answer now. "
         + "Use only SELECT <gap_id> C001 :: <reason>, UNRESOLVED <gap_id> :: <reason>, and END. "
         + "Do not output node ids, provenance edge ids, event ids, or bare numbers.\n";
   }

   private static boolean needsSelectionCorrection(RepairDecision decision) {
      return decision != null
         && decision.getSelectedRankCount() == 0
         && (decision.getValidLineCount() == 0 || decision.getIgnoredLineCount() > 0);
   }

   private static LlmRepairResult.AgentPhase phase(String prompt, LlmConnectivityProbe.LlmChatResult result,
      int validLineCount, int ignoredLineCount) {
      return new LlmRepairResult.AgentPhase(prompt, result.getMessageText(), result.getFinishReason(), validLineCount, ignoredLineCount);
   }

   private static LlmRepairResult.AgentPhase failedPhase(String prompt, RuntimeException ex) {
      return new LlmRepairResult.AgentPhase(prompt, "ERROR " + describe(ex), "", 0, 0);
   }

   private static String formatGapIds(GraphAssessment assessment) {
      if (assessment == null || assessment.getGaps().isEmpty()) return "none";
      StringBuilder builder = new StringBuilder();
      for (GraphAssessment.Gap gap : assessment.getGaps()) {
         if (builder.length() > 0) builder.append(",");
         builder.append(gap.getGapId());
      }
      return builder.toString();
   }

   private static String formatCandidateTokens(RepairDecision decision) {
      if (decision == null) return "none";
      List<Integer> ranks = new ArrayList<>();
      for (RepairDecision.Selection selection : decision.getSelections()) ranks.addAll(selection.getRanks());
      return formatCandidateRanks(ranks);
   }

   private static String formatCandidateTokens(List<LlmRepairSelectedEdge> selected) {
      return formatCandidateRanks(selectedRanks(selected));
   }

   private static String formatCandidateRanks(List<Integer> ranks) {
      if (ranks == null || ranks.isEmpty()) return "none";
      StringBuilder builder = new StringBuilder();
      for (Integer rank : ranks) {
         if (rank == null) continue;
         if (builder.length() > 0) builder.append(",");
         builder.append(LlmRepairCandidateEdge.formatToken(rank.intValue()));
      }
      return builder.length() == 0 ? "none" : builder.toString();
   }

   private static String formatRejected(List<String> rejected) {
      if (rejected == null || rejected.isEmpty()) return "none";
      StringBuilder builder = new StringBuilder();
      for (String reason : rejected) {
         if (builder.length() > 0) builder.append("; ");
         builder.append(reason);
      }
      return builder.toString();
   }

   private static int countAddedEdges(List<LlmRepairResult.LlmRepairRoundResult> rounds) {
      int count = 0;
      if (rounds != null) for (LlmRepairResult.LlmRepairRoundResult round : rounds) count += round.getAddedEdges().size();
      return count;
   }

   private static LlmRepairResult.LlmRepairRoundResult emptyRound(int cycle, LlmRepairResult.AgentPhase assessment,
      GraphAssessment graphAssessment, DirectedPseudograph<EntityNode, EventEdge> current) {
      return round(cycle, assessment, LlmRepairResult.AgentPhase.empty(), graphAssessment,
         new ArrayList<LlmRepairNode>(), new ArrayList<LlmRepairCandidateEdge>(), new ArrayList<LlmRepairSelectedEdge>(),
         new ArrayList<EventEdge>(), current);
   }

   private static LlmRepairResult.LlmRepairRoundResult round(int cycle, LlmRepairResult.AgentPhase assessment,
      LlmRepairResult.AgentPhase selection, GraphAssessment graphAssessment,
      List<LlmRepairNode> anchors, List<LlmRepairCandidateEdge> candidates, List<LlmRepairSelectedEdge> selected,
      List<EventEdge> added, DirectedPseudograph<EntityNode, EventEdge> current) {
      return new LlmRepairResult.LlmRepairRoundResult(cycle, assessment.getPrompt(), assessment.getResponse(),
         selection.getPrompt(), selection.getResponse(), gapIds(graphAssessment), graphAssessment.getSummary(), graphAssessment.getSummary(),
         anchors, candidates, selected, added, copyGraph(current));
   }

   private static void appendContext(StringBuilder builder, LlmAttackStoryContext context) {
      builder.append("INVESTIGATION_CONTEXT\n");
      if (context != null) {
         builder.append("anomaly=").append(formatNode(context.getAnomalyNode())).append("\n");
         for (LlmSelectionCandidate candidate : context.getSelectedCandidates()) builder.append("entry=").append(formatNode(candidate.getEntry())).append("\n");
      }
   }

   private static String serializeGraph(DirectedPseudograph<EntityNode, EventEdge> graph) {
      if (graph == null) return "nodes=[]\nedges=[]\n";
      List<EntityNode> nodes = new ArrayList<>(graph.vertexSet());
      nodes.sort(Comparator.comparingLong(EntityNode::getId));
      StringBuilder builder = new StringBuilder("nodes=\n");
      for (EntityNode node : nodes) builder.append(node.getId()).append(" ").append(formatNode(node)).append("\n");
      List<EventEdge> edges = new ArrayList<>(graph.edgeSet());
      edges.sort(Comparator.comparingLong(EventEdge::getID));
      builder.append("edges=\n");
      for (EventEdge edge : edges) {
         builder.append(edge.getID()).append(" ").append(LlmNoiseGraphEdge.formatCompactEdge(edge))
            .append(" [").append(edge.getStartns()).append(",").append(edge.getEndns()).append("]\n");
      }
      return builder.toString();
   }

   private static String formatNode(EntityNode node) {
      if (node == null) return "[Unknown|]";
      String type = node.getP() != null ? "Process" : node.getF() != null ? "File" : node.getN() != null ? "Network" : "Unknown";
      return "[" + type + "|" + node.getSignature() + "]";
   }

   private static List<LlmRepairNode> anchorsForAssessment(GraphAssessment assessment,
      DirectedPseudograph<EntityNode, EventEdge> current) {
      List<LlmRepairNode> anchors = new ArrayList<>();
      if (assessment == null || current == null) return anchors;
      Map<Long, EntityNode> nodesById = new LinkedHashMap<>();
      for (EntityNode node : current.vertexSet()) nodesById.put(node.getId(), node);
      Set<Long> seen = new LinkedHashSet<>();
      int rank = 1;
      for (GraphAssessment.Gap gap : assessment.getGaps()) {
         for (Long nodeId : gap.getAnchorNodeIds()) {
            EntityNode node = nodeId == null ? null : nodesById.get(nodeId);
            if (node != null && seen.add(nodeId)) anchors.add(new LlmRepairNode(rank++, node));
         }
      }
      return anchors;
   }

   static List<LlmRepairCandidateEdge> collectBoundaryCandidates(
      DirectedPseudograph<EntityNode, EventEdge> source,
      DirectedPseudograph<EntityNode, EventEdge> current,
      int max
   ) {
      return collectBoundaryCandidates(
         source,
         current,
         max,
         Collections.<String, Integer>emptyMap(),
         Collections.<String>emptySet(),
         0
      );
   }

   static List<LlmRepairCandidateEdge> collectBoundaryCandidates(
      DirectedPseudograph<EntityNode, EventEdge> source,
      DirectedPseudograph<EntityNode, EventEdge> current,
      int max,
      Map<String, Integer> unselectedDisplayCounts,
      Set<String> excludedEdgeKeys,
      int unselectedCandidatePenalty
   ) {
      List<LlmRepairCandidateEdge> result = new ArrayList<>();
      if (source == null || max <= 0) return result;
      Map<String, Integer> displayCounts = unselectedDisplayCounts == null
         ? Collections.<String, Integer>emptyMap()
         : unselectedDisplayCounts;
      Set<String> excluded = excludedEdgeKeys == null ? Collections.<String>emptySet() : excludedEdgeKeys;
      int penalty = Math.max(0, unselectedCandidatePenalty);
      List<EventEdge> ordered = new ArrayList<>(source.edgeSet());
      ordered.sort(
         Comparator.comparingInt((EventEdge edge) -> effectiveCandidatePriority(edge, current, source, displayCounts, penalty))
            .thenComparingInt(edge -> boundaryPriority(edge, current, source))
            .thenComparingInt(LlmRepairCandidateScorer::eventPriority)
            .thenComparing(LlmRepairCandidateScorer::stableKey)
      );
      int rank = 1;
      for (EventEdge edge : ordered) {
         if (edge == null || (current != null && current.containsEdge(edge))) continue;
         if (excluded.contains(LlmRepairCandidateEdge.edgeKey(edge))) continue;
         int priority = boundaryPriority(edge, current, source);
         result.add(new LlmRepairCandidateEdge(rank++, priority + 1, edge, 0, 0L, "", Collections.<Integer>emptyList()));
         if (result.size() >= max) break;
      }
      return result;
   }

   private static int boundaryPriority(EventEdge edge, DirectedPseudograph<EntityNode, EventEdge> current,
      DirectedPseudograph<EntityNode, EventEdge> candidateGraph) {
      return LlmRepairCandidateScorer.priority(edge, current, candidateGraph);
   }

   private static int effectiveCandidatePriority(EventEdge edge, DirectedPseudograph<EntityNode, EventEdge> current,
      DirectedPseudograph<EntityNode, EventEdge> candidateGraph, Map<String, Integer> unselectedDisplayCounts, int penalty) {
      int basePriority = boundaryPriority(edge, current, candidateGraph);
      if (penalty <= 0 || unselectedDisplayCounts == null) return basePriority;
      Integer displayCount = unselectedDisplayCounts.get(LlmRepairCandidateEdge.edgeKey(edge));
      if (displayCount == null || displayCount.intValue() <= 0) return basePriority;
      long effectivePriority = (long)basePriority + (long)displayCount.intValue() * (long)penalty;
      return effectivePriority > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int)effectivePriority;
   }

   private static int countPenalizedCandidates(List<LlmRepairCandidateEdge> candidates, Map<String, Integer> unselectedDisplayCounts,
      int unselectedCandidatePenalty) {
      if (unselectedCandidatePenalty <= 0 || candidates == null || unselectedDisplayCounts == null || unselectedDisplayCounts.isEmpty()) return 0;
      int count = 0;
      for (LlmRepairCandidateEdge candidate : candidates) {
         Integer displayCount = unselectedDisplayCounts.get(LlmRepairCandidateEdge.edgeKey(candidate.getEdge()));
         if (displayCount != null && displayCount.intValue() > 0) count++;
      }
      return count;
   }

   private static boolean hasUnseenCandidate(DirectedPseudograph<EntityNode, EventEdge> source,
      DirectedPseudograph<EntityNode, EventEdge> current, Set<String> excludedEdgeKeys,
      Map<String, Integer> unselectedDisplayCounts) {
      if (source == null) return false;
      Set<String> excluded = excludedEdgeKeys == null ? Collections.<String>emptySet() : excludedEdgeKeys;
      Map<String, Integer> displayCounts = unselectedDisplayCounts == null
         ? Collections.<String, Integer>emptyMap()
         : unselectedDisplayCounts;
      for (EventEdge edge : source.edgeSet()) {
         if (edge == null || (current != null && current.containsEdge(edge))) continue;
         String edgeKey = LlmRepairCandidateEdge.edgeKey(edge);
         if (!excluded.contains(edgeKey) && !displayCounts.containsKey(edgeKey)) return true;
      }
      return false;
   }

   private static boolean hasUnseenGapCandidate(DirectedPseudograph<EntityNode, EventEdge> source,
      DirectedPseudograph<EntityNode, EventEdge> current, Set<String> eligibleEdgeKeys, Set<String> excludedEdgeKeys,
      Map<String, Integer> unselectedDisplayCounts) {
      if (source == null || eligibleEdgeKeys == null || eligibleEdgeKeys.isEmpty()) return false;
      Set<String> excluded = excludedEdgeKeys == null ? Collections.<String>emptySet() : excludedEdgeKeys;
      Map<String, Integer> displayCounts = unselectedDisplayCounts == null
         ? Collections.<String, Integer>emptyMap()
         : unselectedDisplayCounts;
      for (EventEdge edge : source.edgeSet()) {
         if (edge == null || (current != null && current.containsEdge(edge))) continue;
         String edgeKey = LlmRepairCandidateEdge.edgeKey(edge);
         if (eligibleEdgeKeys.contains(edgeKey) && !excluded.contains(edgeKey) && !displayCounts.containsKey(edgeKey)) return true;
      }
      return false;
   }

   private static int recordUnselectedCandidates(List<LlmRepairCandidateEdge> candidates, Set<String> selectedCandidateEdgeKeys,
      Map<String, Integer> unselectedDisplayCounts) {
      if (candidates == null || unselectedDisplayCounts == null) return 0;
      int count = 0;
      Set<String> selected = selectedCandidateEdgeKeys == null ? Collections.<String>emptySet() : selectedCandidateEdgeKeys;
      for (LlmRepairCandidateEdge candidate : candidates) {
         String edgeKey = LlmRepairCandidateEdge.edgeKey(candidate.getEdge());
         if (selected.contains(edgeKey)) continue;
         Integer previous = unselectedDisplayCounts.get(edgeKey);
         unselectedDisplayCounts.put(edgeKey, previous == null ? 1 : previous.intValue() + 1);
         count++;
      }
      return count;
   }

   private static List<Integer> selectedRanks(List<LlmRepairSelectedEdge> selected) {
      List<Integer> ranks = new ArrayList<>();
      if (selected == null) return ranks;
      for (LlmRepairSelectedEdge edge : selected) ranks.add(edge.getRank());
      return ranks;
   }

   private static DirectedPseudograph<EntityNode, EventEdge> candidatePoolWithoutConfirmedEdges(
      DirectedPseudograph<EntityNode, EventEdge> candidatePool,
      DirectedPseudograph<EntityNode, EventEdge> currentConfirmedGraph
   ) {
      DirectedPseudograph<EntityNode, EventEdge> result = new DirectedPseudograph(EventEdge.class);
      if (candidatePool == null) return result;
      Set<String> confirmedKeys = new LinkedHashSet<>();
      if (currentConfirmedGraph != null) {
         for (EventEdge edge : currentConfirmedGraph.edgeSet()) confirmedKeys.add(LlmRepairCandidateEdge.edgeKey(edge));
      }
      for (EventEdge edge : candidatePool.edgeSet()) {
         if (confirmedKeys.contains(LlmRepairCandidateEdge.edgeKey(edge))) continue;
         if (!result.containsVertex(edge.getSource())) result.addVertex(edge.getSource());
         if (!result.containsVertex(edge.getSink())) result.addVertex(edge.getSink());
         result.addEdge(edge.getSource(), edge.getSink(), edge);
      }
      return result;
   }

   private static List<String> gapIds(GraphAssessment assessment) {
      List<String> ids = new ArrayList<>();
      if (assessment != null) for (GraphAssessment.Gap gap : assessment.getGaps()) ids.add(gap.getGapId());
      return ids;
   }

   private static boolean containsEdgeKey(List<EventEdge> edges, EventEdge candidate) {
      if (edges == null || candidate == null) return false;
      String key = LlmRepairCandidateEdge.edgeKey(candidate);
      for (EventEdge edge : edges) if (key.equals(LlmRepairCandidateEdge.edgeKey(edge))) return true;
      return false;
   }

   private static String describe(Throwable ex) {
      return ex == null ? "unknown" : (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage());
   }

   private static DirectedPseudograph<EntityNode, EventEdge> copyGraph(DirectedPseudograph<EntityNode, EventEdge> source) {
      DirectedPseudograph<EntityNode, EventEdge> copy = new DirectedPseudograph(EventEdge.class);
      if (source == null) return copy;
      for (EntityNode node : source.vertexSet()) copy.addVertex(node);
      for (EventEdge edge : source.edgeSet()) if (!copy.containsEdge(edge)) copy.addEdge(edge.getSource(), edge.getSink(), edge);
      return copy;
   }
}
