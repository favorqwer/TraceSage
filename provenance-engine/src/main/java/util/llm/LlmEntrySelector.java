package util.llm;

import gql.LlmClause;
import gql.WithQuery;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import main.Main;
import model.EntityNode;
import model.EventEdge;
import model.PoiEventInfo;
import org.json.JSONArray;
import org.json.JSONObject;

public class LlmEntrySelector {
   private final LlmConnectivityProbe connectivityProbe;
   private final LlmEvidencePromptBuilder promptBuilder;

   public LlmEntrySelector() {
      this(new LlmConnectivityProbe(), new LlmEvidencePromptBuilder());
   }

   public LlmEntrySelector(LlmConnectivityProbe connectivityProbe, LlmEvidencePromptBuilder promptBuilder) {
      this.connectivityProbe = connectivityProbe;
      this.promptBuilder = promptBuilder;
   }

   public LlmSelectionResult selectEntries(
      List<EntityNode> topEntryLst, List<LlmEvidencePathResult> evidencePaths, WithQuery withQuery
   ) {
      LlmClause llmClause = withQuery == null ? null : withQuery.getLlmClause();
      if (llmClause == null) {
         throw new IllegalStateException("LLM entry selection requested without an LLM clause.");
      }

      int maxSelections = Math.min(llmClause.getTopK(), topEntryLst.size());
      if (maxSelections <= 0) {
         throw new IllegalStateException("LLM TOP N resolved to zero selectable candidates.");
      }

      if (evidencePaths == null || evidencePaths.size() != topEntryLst.size()) {
         throw new IllegalStateException(
            "LLM evidence paths are incomplete. Expected " + topEntryLst.size() + " paths but got " + (evidencePaths == null ? 0 : evidencePaths.size()) + "."
         );
      }

      System.out.println("LLM entry selection enabled: " + llmClause);
      LlmConfig config = LlmConfig.load();

      String systemPrompt = this.promptBuilder.buildSystemPrompt(maxSelections);
      String userPrompt = this.promptBuilder.buildUserPrompt(evidencePaths, maxSelections);
      LlmSelectionQuestionRecord questionRecord = new LlmSelectionQuestionRecord(
         config.getProvider(), config.getEndpoint(), config.getModel(), maxSelections, systemPrompt, userPrompt
      );
      if (topEntryLst.size() <= maxSelections) {
         return selectOnlyCandidateWithoutCallingLlm(questionRecord, topEntryLst);
      }

      LlmConnectivityProbe.LlmChatResult chatResult = this.connectivityProbe.chatCompletion(config, systemPrompt, userPrompt);
      JSONObject json = new JSONObject(LlmConnectivityProbe.extractJsonObjectText(chatResult.getMessageText()));
      return parseSelectionResult(questionRecord, json, topEntryLst, maxSelections, chatResult);
   }

   private static LlmSelectionResult selectOnlyCandidateWithoutCallingLlm(LlmSelectionQuestionRecord questionRecord, List<EntityNode> topEntryLst) {
      List<EntityNode> selectedEntries = new ArrayList<>(topEntryLst);
      List<Integer> selectedCandidateRanks = new ArrayList<>();
      List<LlmSelectionCandidate> rankedResults = new ArrayList<>();
      for (int i = 0; i < topEntryLst.size(); i++) {
         int candidateRank = i + 1;
         selectedCandidateRanks.add(candidateRank);
         rankedResults.add(
            new LlmSelectionCandidate(
               candidateRank,
               candidateRank,
               topEntryLst.get(i),
               "Deterministic selection because all candidates fit within LLM TOP N."
            )
         );
      }

      String summary = "Deterministic selection: candidate count is less than or equal to LLM TOP N, so no external LLM request was needed.";
      logSelectedEntries(rankedResults, summary);
      return new LlmSelectionResult(questionRecord, selectedEntries, rankedResults, selectedCandidateRanks, summary, "", 0);
   }

   static LlmSelectionResult parseSelectionResult(
      LlmSelectionQuestionRecord questionRecord,
      JSONObject json,
      List<EntityNode> topEntryLst,
      int maxSelections,
      LlmConnectivityProbe.LlmChatResult chatResult
   ) {
      if (!json.has("selected_candidate_ranks")) {
         throw new IllegalStateException("LLM response is missing selected_candidate_ranks.");
      }

      Map<Integer, EntityNode> entryByCandidateRank = new LinkedHashMap<>();
      for (int i = 0; i < topEntryLst.size(); i++) {
         entryByCandidateRank.put(i + 1, topEntryLst.get(i));
      }

      JSONArray selectedRanksJson = json.getJSONArray("selected_candidate_ranks");
      Set<Integer> selectedCandidateRanks = new LinkedHashSet<>();
      for (int i = 0; i < selectedRanksJson.length(); i++) {
         int candidateRank = selectedRanksJson.getInt(i);
         if (!entryByCandidateRank.containsKey(candidateRank)) {
            throw new IllegalStateException("LLM selected unknown candidate rank: " + candidateRank);
         }
         if (!selectedCandidateRanks.add(candidateRank)) {
            throw new IllegalStateException("LLM selected the same candidate rank more than once: " + candidateRank);
         }
      }

      Map<Integer, String> reasonByCandidateRank = new LinkedHashMap<>();
      if (json.has("ranked_candidates")) {
         JSONArray rankedCandidates = json.getJSONArray("ranked_candidates");
         for (int i = 0; i < rankedCandidates.length(); i++) {
            JSONObject candidate = rankedCandidates.getJSONObject(i);
            int candidateRank = candidate.getInt("candidate_rank");
            if (!entryByCandidateRank.containsKey(candidateRank)) {
               throw new IllegalStateException("LLM ranked an unknown candidate rank: " + candidateRank);
            }
            reasonByCandidateRank.put(candidateRank, candidate.optString("reason", ""));
         }
      }

      if (selectedCandidateRanks.isEmpty()) {
         throw new IllegalStateException("LLM selected zero candidate entries.");
      }

      if (selectedCandidateRanks.size() > maxSelections) {
         throw new IllegalStateException(
            "LLM selected " + selectedCandidateRanks.size() + " entries, exceeding the limit of " + maxSelections + "."
         );
      }

      List<EntityNode> selectedEntries = new ArrayList<>();
      List<LlmSelectionCandidate> rankedResults = new ArrayList<>();
      int rank = 1;
      for (Integer candidateRank : selectedCandidateRanks) {
         EntityNode entry = entryByCandidateRank.get(candidateRank);
         rankedResults.add(new LlmSelectionCandidate(
            rank++, candidateRank, entry, reasonByCandidateRank.getOrDefault(candidateRank, "")
         ));
         selectedEntries.add(entry);
      }

      String summary = json.optString("summary", "");
      logSelectedEntries(rankedResults, summary);
      return new LlmSelectionResult(
         questionRecord,
         selectedEntries,
         rankedResults,
         new ArrayList<>(selectedCandidateRanks),
         summary,
         chatResult.getMessageText(),
         chatResult.getStatusCode()
      );
   }

   private static void logSelectedEntries(List<LlmSelectionCandidate> rankedResults, String summary) {
      System.out.println("LLM selected " + rankedResults.size() + " candidate entries:");
      for (LlmSelectionCandidate candidate : rankedResults) {
         System.out.println(
            "  ["
               + candidate.getRank()
               + "] candidate_rank="
               + candidate.getCandidateRank()
               + ", id="
               + candidate.getEntryId()
               + ", signature="
               + candidate.getSignature()
               + ", composite_score="
               + candidate.getCompositeScore()
         );
      }
   }

}

class LlmEvidencePromptBuilder {
   public String buildSystemPrompt(int maxSelections) {
      return "You are selecting the most likely attack entry candidates in a provenance graph. "
         + "Base every decision only on the provided evidence. Select at least 1 and at most "
         + maxSelections
         + " candidates. "
         + "Return strict JSON only, with no markdown fences or extra text.";
   }

   public String buildUserPrompt(List<LlmEvidencePathResult> evidencePaths, int maxSelections) {
      StringBuilder builder = new StringBuilder();
      builder.append("Task: compare the following candidate provenance paths and select the most likely attack-entry candidates. Select at most ")
         .append(maxSelections)
         .append(" candidate nodes.")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Each candidate can include multiple differentiated evidence paths. Evaluate the complete path set for a candidate; path numbers are evidence labels only and are not valid output selectors.")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Valid candidate ranks only: ");

      for (int i = 0; i < evidencePaths.size(); i++) {
         if (i > 0) {
            builder.append(", ");
         }
         builder.append(i + 1);
      }

      builder.append(System.lineSeparator())
         .append("You must select by candidate rank only. Do not output entry ids, node ids, edge ids, or any other ids.")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Candidate composite_score is a within-entity-type pre-ranking signal computed from normalized graph-derived impact and normalized early causal-entry time using the configured ranking weights (default: impact 0.7, time 0.3). The time score uses the earliest first-hop event time on a causal path to the current POI. ")
         .append("It excludes unrelated historical activity. Composite score is supporting evidence only: it must not override path event semantics, causal-chain completeness, or the candidate's attack role. Do not select by composite score alone.")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Output format:")
         .append(System.lineSeparator())
         .append("{\"selected_candidate_ranks\":[1,2],\"ranked_candidates\":[{\"candidate_rank\":1,\"rank\":1,\"reason\":\"...\"},{\"candidate_rank\":2,\"rank\":2,\"reason\":\"...\"}],\"summary\":\"...\"}")
         .append(System.lineSeparator())
         .append(System.lineSeparator());

      appendPoiEvent(builder, findPoiEvidencePath(evidencePaths));
      builder.append(System.lineSeparator());

      for (int i = 0; i < evidencePaths.size(); i++) {
         appendEvidence(builder, evidencePaths.get(i), i + 1);
      }

      builder.append("Rules:")
         .append(System.lineSeparator())
         .append("1. selected_candidate_ranks must contain between 1 and ")
         .append(maxSelections)
         .append(" ranks.")
         .append(System.lineSeparator())
         .append("2. Every selected rank must come from the provided candidate ranks only, and a rank may appear only once.")
         .append(System.lineSeparator())
         .append("3. ranked_candidates, when provided, must use the same candidate ranks and order as selected_candidate_ranks.")
         .append(System.lineSeparator())
         .append("4. Never output entry ids, node ids, edge ids, or candidate signatures as selectors.")
         .append(System.lineSeparator())
         .append("5. Base the decision on the provided path evidence, event semantics, causal-chain completeness, and attack role; use composite score only as supporting context.")
         .append(System.lineSeparator())
         .append("6. Select the candidates most likely to be attack-entry points; do not select merely to fill the TOP N limit.")
         .append(System.lineSeparator())
         .append("7. Use concise reasons grounded only in the provided path evidence.")
         .append(System.lineSeparator())
         .append("8. Use agreement across differentiated paths as stronger support for a candidate; path numbers are evidence labels, not selection targets.")
         .append(System.lineSeparator());
      return builder.toString();
   }

   private static void appendEvidence(StringBuilder builder, LlmEvidencePathResult result, int rank) {
      EntityNode entry = result.getEntry();
      builder.append("Candidate #")
         .append(rank)
         .append(System.lineSeparator())
         .append("entry: type=")
         .append(resolveNodeType(entry))
         .append(", signature=")
         .append(entry == null ? "" : entry.getSignature())
         .append(", composite_score=")
         .append(entry == null ? 0.0 : Main.getEntryCompositeScore(entry))
         .append(System.lineSeparator());

      if (!result.isMatched()) {
         builder.append("path_search_status: ")
            .append(result.getSearchStatus().name())
            .append(System.lineSeparator())
            .append("message: ")
            .append(result.getMessage())
            .append(System.lineSeparator())
            .append(System.lineSeparator());
         return;
      }

      builder.append("attack_path:")
         .append(System.lineSeparator());
      for (LlmEvidencePath path : result.getPaths()) {
         builder.append("Path #")
            .append(path.getPathRank())
            .append(": base_score=")
            .append(path.getBaseScore())
            .append(", diversity_adjusted_score=")
            .append(path.getSelectionScore())
            .append(", max_overlap=")
            .append(path.getMaxOverlap())
            .append(System.lineSeparator());
         appendAttackPath(builder, path.getOrderedNodes(), path.getOrderedEdges());
         builder.append(System.lineSeparator());
      }
      builder.append("path_search_status: ")
         .append(result.getSearchStatus().name())
         .append(System.lineSeparator());
      if (result.getSearchStatus() == LlmEvidencePathSearchStatus.TRUNCATED) {
         builder.append("path_search_note: evidence path enumeration reached its state limit; the displayed path count is incomplete.")
            .append(System.lineSeparator());
      } else if (result.getSearchStatus() == LlmEvidencePathSearchStatus.EXHAUSTIVE_SINGLE_PATH) {
         builder.append("path_search_note: exhaustive enumeration found only one differentiated evidence path.")
            .append(System.lineSeparator());
      }
      builder.append(System.lineSeparator()).append(System.lineSeparator());
   }

   private static void appendAttackPath(StringBuilder builder, List<EntityNode> orderedNodes, List<EventEdge> orderedEdges) {
      if (orderedNodes.isEmpty()) {
         return;
      }

      builder.append(formatNode(orderedNodes.get(0)));
      for (int i = 0; i < orderedEdges.size(); i++) {
         EventEdge edge = orderedEdges.get(i);
         builder.append(System.lineSeparator())
            .append("--")
            .append(edge.getEvent())
            .append("-->")
            .append(System.lineSeparator());

         if (i + 1 < orderedNodes.size()) {
            builder.append(formatNode(orderedNodes.get(i + 1)));
         }
      }
   }

   private static String formatNode(EntityNode node) {
      return "[" + resolveNodeType(node) + "|" + (node == null ? "" : node.getSignature()) + "]";
   }

   private static LlmEvidencePathResult findPoiEvidencePath(List<LlmEvidencePathResult> evidencePaths) {
      if (evidencePaths == null || evidencePaths.isEmpty()) {
         return null;
      }
      for (LlmEvidencePathResult evidencePath : evidencePaths) {
         if (evidencePath != null && evidencePath.getPoiEdge() != null) {
            return evidencePath;
         }
      }
      return evidencePaths.get(0);
   }

   private static void appendPoiEvent(StringBuilder builder, LlmEvidencePathResult result) {
      EventEdge poiEdge = result == null ? null : result.getPoiEdge();
      PoiEventInfo poiEventInfo = Main.poiEventInfo;
      builder.append("poi_event:").append(System.lineSeparator());

      if (poiEdge != null) {
         builder.append("source: ")
            .append(formatNode(poiEdge.getSource()))
            .append(System.lineSeparator())
            .append("event: ")
            .append(formatOptionalValue(poiEdge.getEvent()))
            .append(System.lineSeparator())
            .append("sink: ")
            .append(formatNode(poiEdge.getSink()))
            .append(System.lineSeparator())
            .append("start_time: ")
            .append(formatOptionalValue(poiEdge.getStartTime()))
            .append(System.lineSeparator())
            .append("end_time: ")
            .append(formatOptionalValue(poiEdge.getEndTime()))
            .append(System.lineSeparator());
         return;
      }

      if (poiEventInfo != null) {
         builder.append("source_signature: ")
            .append(formatOptionalValue(poiEventInfo.getSourceSignature()))
            .append(System.lineSeparator())
            .append("event: ")
            .append(formatOptionalValue(poiEventInfo.getEventType()))
            .append(System.lineSeparator())
            .append("sink_signature: ")
            .append(formatOptionalValue(poiEventInfo.getSinkSignature()))
            .append(System.lineSeparator())
            .append("start_time: ")
            .append(formatOptionalValue(poiEventInfo.getStartTime()))
            .append(System.lineSeparator())
            .append("end_time: ")
            .append(formatOptionalValue(poiEventInfo.getEndTime()))
            .append(System.lineSeparator());
         return;
      }

      builder.append("<unavailable>").append(System.lineSeparator());
   }

   private static String formatOptionalValue(Object value) {
      if (value == null) {
         return "<unknown>";
      }
      String text = value.toString().trim();
      return text.isEmpty() ? "<unknown>" : text;
   }

   private static String resolveNodeType(EntityNode node) {
      if (node == null) {
         return "Unknown";
      }
      if (node.getN() != null) {
         return "Network";
      }
      if (node.getP() != null) {
         return "Process";
      }
      if (node.getF() != null) {
         return "File";
      }
      return "Unknown";
   }
}
