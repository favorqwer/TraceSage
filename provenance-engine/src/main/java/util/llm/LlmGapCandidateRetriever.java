package util.llm;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

/** Builds a bounded, GAP-specific candidate window from real provenance edges. */
final class LlmGapCandidateRetriever {
   RetrievalResult retrieve(
      GraphAssessment assessment,
      DirectedPseudograph<EntityNode, EventEdge> current,
      DirectedPseudograph<EntityNode, EventEdge> source,
      int maxCandidates,
      int maxAnchorHops,
      Map<String, Integer> displayCounts,
      Set<String> excludedEdgeKeys
   ) {
      if (assessment == null || assessment.getGaps().isEmpty() || source == null || maxCandidates <= 0) {
         return RetrievalResult.empty();
      }
      Map<Long, EntityNode> nodesById = collectNodes(current, source);
      int hops = 1;
      Map<Long, Set<Long>> adjacency = collectAdjacency(current);
      Map<String, List<GapMatch>> matchesByGap = new LinkedHashMap<>();
      Map<String, String> diagnostics = new LinkedHashMap<>();
      Set<String> eligibleEdgeKeys = new LinkedHashSet<>();
      List<GraphAssessment.Gap> gaps = sortedGaps(assessment.getGaps());

      for (GraphAssessment.Gap gap : gaps) {
         List<Long> anchorIds = validAnchorIds(gap, current, nodesById);
         if (anchorIds.isEmpty()) {
            matchesByGap.put(gap.getGapId(), Collections.<GapMatch>emptyList());
            diagnostics.put(gap.getGapId(), "no_valid_anchors");
            continue;
         }
         Map<Long, Integer> distances = distances(adjacency, anchorIds, hops);
         Map<String, GapMatch> uniqueMatches = new LinkedHashMap<>();
         List<GapMatch> matches = new ArrayList<>();
         for (EventEdge edge : source.edgeSet()) {
            if (!isEligibleEdge(edge, current, excludedEdgeKeys)) continue;
            int distance = edgeDistance(edge, distances);
            if (distance > hops) continue;
            long anchorId = nearestAnchor(edge, anchorIds, adjacency, hops);
            EntityNode anchor = nodesById.get(anchorId);
            List<String> signals = semanticSignals(gap, edge, anchorIds);
            String logicalKey = LlmRepairCandidateEdge.edgeKey(edge);
            GapMatch existing = uniqueMatches.get(logicalKey);
            if (existing == null) uniqueMatches.put(logicalKey, new GapMatch(gap, edge, anchor, distance, signals, displayCount(displayCounts, edge)));
            else existing.addEquivalent(edge);
            eligibleEdgeKeys.add(logicalKey);
         }
         matches.addAll(uniqueMatches.values());
         Collections.sort(matches, GAP_MATCH_COMPARATOR);
         matchesByGap.put(gap.getGapId(), matches);
         diagnostics.put(gap.getGapId(), matches.isEmpty() ? "no_local_candidate_edges" : "eligible=" + matches.size());
      }
      return buildResult(gaps, matchesByGap, diagnostics, eligibleEdgeKeys, maxCandidates);
   }

   private static RetrievalResult buildResult(List<GraphAssessment.Gap> gaps, Map<String, List<GapMatch>> matchesByGap,
      Map<String, String> diagnostics, Set<String> eligibleEdgeKeys, int maxCandidates) {
      Map<String, CandidateAggregate> selected = new LinkedHashMap<>();
      Map<String, List<GapMatch>> selectedByGap = new LinkedHashMap<>();
      int baseQuota = gaps.isEmpty() ? 0 : maxCandidates / gaps.size();
      int remainder = gaps.isEmpty() ? 0 : maxCandidates % gaps.size();
      for (int gapIndex = 0; gapIndex < gaps.size(); gapIndex++) {
         GraphAssessment.Gap gap = gaps.get(gapIndex);
         int quota = baseQuota + (gapIndex < remainder ? 1 : 0);
         List<GapMatch> selectedForGap = new ArrayList<>();
         List<GapMatch> matches = matchesByGap.get(gap.getGapId());
         if (matches != null) {
            for (GapMatch match : matches) {
               if (selectedForGap.size() >= quota) break;
               selectedForGap.add(match);
               addMatch(selected, match);
            }
         }
         selectedByGap.put(gap.getGapId(), selectedForGap);
      }

      List<LlmRepairCandidateEdge> candidates = new ArrayList<>();
      Map<String, List<Integer>> ranksByGap = new LinkedHashMap<>();
      int rank = 1;
      for (CandidateAggregate aggregate : selected.values()) {
         LlmRepairCandidateEdge candidate = aggregate.toCandidate(rank++);
         candidates.add(candidate);
         for (String gapId : candidate.getGapIds()) {
            List<Integer> ranks = ranksByGap.get(gapId);
            if (ranks == null) {
               ranks = new ArrayList<>();
               ranksByGap.put(gapId, ranks);
            }
            ranks.add(candidate.getRank());
         }
      }
      Map<String, Integer> candidateCountsByGap = new LinkedHashMap<>();
      for (GraphAssessment.Gap gap : gaps) {
         List<Integer> ranks = ranksByGap.get(gap.getGapId());
         candidateCountsByGap.put(gap.getGapId(), ranks == null ? 0 : ranks.size());
      }
      return new RetrievalResult(candidates, candidateCountsByGap, diagnostics, ranksByGap, eligibleEdgeKeys);
   }

   private static void addMatch(Map<String, CandidateAggregate> selected, GapMatch match) {
      String key = LlmRepairCandidateEdge.edgeKey(match.edge);
      CandidateAggregate aggregate = selected.get(key);
      if (aggregate == null) {
         aggregate = new CandidateAggregate(match);
         selected.put(key, aggregate);
      } else {
         aggregate.add(match);
      }
   }

   private static Map<Long, EntityNode> collectNodes(DirectedPseudograph<EntityNode, EventEdge> current,
      DirectedPseudograph<EntityNode, EventEdge> source) {
      Map<Long, EntityNode> result = new LinkedHashMap<>();
      addNodes(result, current);
      addNodes(result, source);
      return result;
   }

   private static void addNodes(Map<Long, EntityNode> target, DirectedPseudograph<EntityNode, EventEdge> graph) {
      if (graph == null) return;
      for (EntityNode node : graph.vertexSet()) if (node != null && !target.containsKey(node.getId())) target.put(node.getId(), node);
   }

   private static Map<Long, Set<Long>> collectAdjacency(DirectedPseudograph<EntityNode, EventEdge> current) {
      Map<Long, Set<Long>> result = new LinkedHashMap<>();
      addAdjacency(result, current);
      return result;
   }

   private static void addAdjacency(Map<Long, Set<Long>> adjacency, DirectedPseudograph<EntityNode, EventEdge> graph) {
      if (graph == null) return;
      for (EventEdge edge : graph.edgeSet()) {
         if (edge == null || edge.getSource() == null || edge.getSink() == null) continue;
         addNeighbor(adjacency, edge.getSource().getId(), edge.getSink().getId());
         addNeighbor(adjacency, edge.getSink().getId(), edge.getSource().getId());
      }
   }

   private static void addNeighbor(Map<Long, Set<Long>> adjacency, long from, long to) {
      Set<Long> neighbors = adjacency.get(from);
      if (neighbors == null) {
         neighbors = new LinkedHashSet<>();
         adjacency.put(from, neighbors);
      }
      neighbors.add(to);
   }

   private static List<GraphAssessment.Gap> sortedGaps(List<GraphAssessment.Gap> gaps) {
      List<GraphAssessment.Gap> result = new ArrayList<>(gaps);
      Collections.sort(result, new Comparator<GraphAssessment.Gap>() {
         @Override public int compare(GraphAssessment.Gap first, GraphAssessment.Gap second) {
            int priority = Double.compare(second.getPriority(), first.getPriority());
            return priority != 0 ? priority : first.getGapId().compareTo(second.getGapId());
         }
      });
      return result;
   }

   private static List<Long> validAnchorIds(GraphAssessment.Gap gap, DirectedPseudograph<EntityNode, EventEdge> current,
      Map<Long, EntityNode> nodesById) {
      List<Long> result = new ArrayList<>();
      if (gap == null || current == null) return result;
      for (Long anchorId : gap.getAnchorNodeIds()) {
         EntityNode node = anchorId == null ? null : nodesById.get(anchorId);
         if (node != null && current.containsVertex(node)) result.add(anchorId);
      }
      return result;
   }

   private static Map<Long, Integer> distances(Map<Long, Set<Long>> adjacency, List<Long> anchors, int maxHops) {
      Map<Long, Integer> result = new LinkedHashMap<>();
      Queue<Long> queue = new ArrayDeque<>();
      for (Long anchor : anchors) {
         result.put(anchor, 0);
         queue.add(anchor);
      }
      while (!queue.isEmpty()) {
         Long node = queue.remove();
         int distance = result.get(node);
         if (distance >= maxHops) continue;
         Set<Long> neighbors = adjacency.get(node);
         if (neighbors == null) continue;
         for (Long neighbor : neighbors) {
            if (result.containsKey(neighbor)) continue;
            result.put(neighbor, distance + 1);
            queue.add(neighbor);
         }
      }
      return result;
   }

   private static boolean isEligibleEdge(EventEdge edge, DirectedPseudograph<EntityNode, EventEdge> current,
      Set<String> excludedEdgeKeys) {
      if (edge == null || edge.getSource() == null || edge.getSink() == null || current == null) return false;
      String logicalKey = LlmRepairCandidateEdge.edgeKey(edge);
      if (containsLogicalEdge(current, logicalKey)) return false;
      if (excludedEdgeKeys != null && excludedEdgeKeys.contains(logicalKey)) return false;
      return current.containsVertex(edge.getSource()) || current.containsVertex(edge.getSink());
   }

   private static boolean containsLogicalEdge(DirectedPseudograph<EntityNode, EventEdge> graph, String logicalKey) {
      if (graph == null || logicalKey == null) return false;
      for (EventEdge edge : graph.edgeSet()) if (logicalKey.equals(LlmRepairCandidateEdge.edgeKey(edge))) return true;
      return false;
   }

   private static int edgeDistance(EventEdge edge, Map<Long, Integer> distances) {
      Integer sourceDistance = distances.get(edge.getSource().getId());
      Integer sinkDistance = distances.get(edge.getSink().getId());
      int source = sourceDistance == null ? Integer.MAX_VALUE : sourceDistance.intValue();
      int sink = sinkDistance == null ? Integer.MAX_VALUE : sinkDistance.intValue();
      return Math.min(source, sink);
   }

   private static long nearestAnchor(EventEdge edge, List<Long> anchors, Map<Long, Set<Long>> adjacency, int maxHops) {
      long nearest = anchors.get(0).longValue();
      int nearestDistance = Integer.MAX_VALUE;
      for (Long anchor : anchors) {
         int sourceDistance = distanceFromAnchor(anchor.longValue(), edge.getSource().getId(), adjacency, maxHops);
         int sinkDistance = distanceFromAnchor(anchor.longValue(), edge.getSink().getId(), adjacency, maxHops);
         int distance = Math.min(sourceDistance, sinkDistance);
         if (distance < nearestDistance || (distance == nearestDistance && anchor.longValue() < nearest)) {
            nearest = anchor.longValue();
            nearestDistance = distance;
         }
      }
      return nearest;
   }

   private static int distanceFromAnchor(long anchorId, long nodeId, Map<Long, Set<Long>> adjacency, int maxHops) {
      if (anchorId == nodeId) return 0;
      Queue<Long> queue = new ArrayDeque<>();
      Map<Long, Integer> distances = new LinkedHashMap<>();
      queue.add(anchorId);
      distances.put(anchorId, 0);
      while (!queue.isEmpty()) {
         Long current = queue.remove();
         int distance = distances.get(current);
         if (distance >= maxHops) continue;
         Set<Long> neighbors = adjacency.get(current);
         if (neighbors == null) continue;
         for (Long neighbor : neighbors) {
            if (distances.containsKey(neighbor)) continue;
            int nextDistance = distance + 1;
            if (neighbor.longValue() == nodeId) return nextDistance;
            distances.put(neighbor, nextDistance);
            queue.add(neighbor);
         }
      }
      return Integer.MAX_VALUE;
   }

   private static int displayCount(Map<String, Integer> displayCounts, EventEdge edge) {
      if (displayCounts == null) return 0;
      Integer count = displayCounts.get(LlmRepairCandidateEdge.edgeKey(edge));
      return count == null ? 0 : Math.max(0, count.intValue());
   }

   private static List<String> semanticSignals(GraphAssessment.Gap gap, EventEdge edge, List<Long> anchorIds) {
      List<String> signals = new ArrayList<>();
      String tactic = gap.getAfterTactic().toLowerCase(Locale.ROOT);
      String event = edge.getEvent() == null ? "" : edge.getEvent().toLowerCase(Locale.ROOT);
      String text = endpointText(edge);
      boolean network = edge.getSource().getN() != null || edge.getSink().getN() != null;
      boolean touchesAnchor = anchorIds.contains(edge.getSource().getId()) || anchorIds.contains(edge.getSink().getId());
      if (tactic.contains("persistence") && containsAny(text, "systemctl", "systemd", ".service", ".timer", "service", "timer", "cron", "autostart")) {
         signals.add("persistence_unit");
      }
      if (tactic.contains("exfiltration")) {
         if (network || containsAny(event, "sendto", "sendmsg", "connect", "write_socket")) signals.add("exfil_network");
         if (touchesAnchor && containsAny(text, "tar", "zip", "gzip", "archive", ".tgz", ".zip")) signals.add("exfil_archive_anchor");
      }
      if (tactic.contains("execution") && ("execve".equals(event) || containsAny(text, "bash", "/bin/sh", "python", "perl", "systemctl"))) {
         signals.add("execution_process");
      }
      if (tactic.contains("command-and-control") && (network || containsAny(text, "curl", "wget", "http", "https"))) {
         signals.add("command_control_network");
      }
      if (tactic.contains("collection") && containsAny(text, "tar", "zip", "gzip", "passwd", "shadow", "credential", "secret")) {
         signals.add("collection_artifact");
      }
      if (tactic.contains("discovery") && containsAny(text, "/usr/bin/ps", "/usr/bin/ss", "uname", "ifconfig", "ip addr")) {
         signals.add("discovery_command");
      }
      if (tactic.contains("initial-access") && (network || containsAny(text, "curl", "wget", "download"))) {
         signals.add("initial_access_network");
      }
      if (signals.isEmpty() && touchesAnchor) signals.add("anchor_local");
      return signals;
   }

   private static boolean containsAny(String value, String... terms) {
      if (value == null || value.isEmpty()) return false;
      for (String term : terms) if (value.contains(term)) return true;
      return false;
   }

   private static String endpointText(EventEdge edge) {
      return (signature(edge.getSource()) + " " + signature(edge.getSink())).toLowerCase(Locale.ROOT);
   }

   private static String signature(EntityNode node) { return node == null || node.getSignature() == null ? "" : node.getSignature(); }

   private static final Comparator<GapMatch> GAP_MATCH_COMPARATOR = new Comparator<GapMatch>() {
      @Override public int compare(GapMatch first, GapMatch second) {
         int semantic = Integer.compare(first.semanticRank(), second.semanticRank());
         if (semantic != 0) return semantic;
         int distance = Integer.compare(first.distance, second.distance);
         if (distance != 0) return distance;
         int dependency = Integer.compare(LlmRepairCandidateScorer.systemDependencyPenalty(first.edge),
            LlmRepairCandidateScorer.systemDependencyPenalty(second.edge));
         if (dependency != 0) return dependency;
         int displayed = Integer.compare(first.displayCount, second.displayCount);
         if (displayed != 0) return displayed;
         int event = Integer.compare(LlmRepairCandidateScorer.eventPriority(first.edge), LlmRepairCandidateScorer.eventPriority(second.edge));
         if (event != 0) return event;
         return LlmRepairCandidateScorer.stableKey(first.edge).compareTo(LlmRepairCandidateScorer.stableKey(second.edge));
      }
   };

   static final class RetrievalResult {
      private final List<LlmRepairCandidateEdge> candidates;
      private final Map<String, Integer> candidateCountsByGap;
      private final Map<String, String> diagnosticsByGap;
      private final Map<String, List<Integer>> ranksByGap;
      private final Set<String> eligibleEdgeKeys;

      RetrievalResult(List<LlmRepairCandidateEdge> candidates, Map<String, Integer> candidateCountsByGap,
         Map<String, String> diagnosticsByGap, Map<String, List<Integer>> ranksByGap, Set<String> eligibleEdgeKeys) {
         this.candidates = Collections.unmodifiableList(new ArrayList<>(candidates));
         this.candidateCountsByGap = Collections.unmodifiableMap(new LinkedHashMap<>(candidateCountsByGap));
         this.diagnosticsByGap = Collections.unmodifiableMap(new LinkedHashMap<>(diagnosticsByGap));
         Map<String, List<Integer>> copiedRanks = new LinkedHashMap<>();
         for (Map.Entry<String, List<Integer>> entry : ranksByGap.entrySet()) copiedRanks.put(entry.getKey(), new ArrayList<>(entry.getValue()));
         this.ranksByGap = Collections.unmodifiableMap(copiedRanks);
         this.eligibleEdgeKeys = Collections.unmodifiableSet(new LinkedHashSet<>(eligibleEdgeKeys));
      }

      static RetrievalResult empty() {
         return new RetrievalResult(Collections.<LlmRepairCandidateEdge>emptyList(), Collections.<String, Integer>emptyMap(),
            Collections.<String, String>emptyMap(), Collections.<String, List<Integer>>emptyMap(), Collections.<String>emptySet());
      }

      List<LlmRepairCandidateEdge> getCandidates() { return candidates; }
      Map<String, Integer> getCandidateCountsByGap() { return candidateCountsByGap; }
      Map<String, String> getDiagnosticsByGap() { return diagnosticsByGap; }
      Map<String, List<Integer>> getRanksByGap() { return ranksByGap; }
      Set<String> getEligibleEdgeKeys() { return eligibleEdgeKeys; }
   }

   private static final class GapMatch {
      final GraphAssessment.Gap gap;
      final EventEdge edge;
      final EntityNode anchor;
      final int distance;
      final List<String> signals;
      final int displayCount;
      final List<Long> equivalentEdgeIds = new ArrayList<>();

      GapMatch(GraphAssessment.Gap gap, EventEdge edge, EntityNode anchor, int distance, List<String> signals, int displayCount) {
         this.gap = gap;
         this.edge = edge;
         this.anchor = anchor;
         this.distance = distance;
         this.signals = signals;
         this.displayCount = displayCount;
         this.equivalentEdgeIds.add(edge.getID());
      }

      void addEquivalent(EventEdge edge) { if (edge != null && !equivalentEdgeIds.contains(edge.getID())) equivalentEdgeIds.add(edge.getID()); }

      int semanticRank() { return signals.contains("anchor_local") || signals.isEmpty() ? 1 : 0; }
   }

   private static final class CandidateAggregate {
      private GapMatch best;
      private final Map<String, GapMatch> matchesByGap = new LinkedHashMap<>();
      private final Set<Long> equivalentEdgeIds = new LinkedHashSet<>();

      CandidateAggregate(GapMatch initial) { add(initial); }

      void add(GapMatch match) {
         matchesByGap.put(match.gap.getGapId(), match);
         equivalentEdgeIds.addAll(match.equivalentEdgeIds);
         if (best == null || GAP_MATCH_COMPARATOR.compare(match, best) < 0) best = match;
      }

      LlmRepairCandidateEdge toCandidate(int rank) {
         List<String> gapIds = new ArrayList<>(matchesByGap.keySet());
         Set<String> signals = new LinkedHashSet<>();
         for (GapMatch match : matchesByGap.values()) signals.addAll(match.signals);
         StringBuilder signalText = new StringBuilder();
         for (String signal : signals) {
            if (signalText.length() > 0) signalText.append(",");
            signalText.append(signal);
         }
         long anchorId = best.anchor == null ? 0L : best.anchor.getId();
         String anchorSignature = best.anchor == null ? "" : best.anchor.getSignature();
         return new LlmRepairCandidateEdge(rank, best.distance, best.edge, 0, anchorId, anchorSignature,
            Collections.<Integer>emptyList(), gapIds, signalText.toString(), new ArrayList<>(equivalentEdgeIds));
      }
   }
}
