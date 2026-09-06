package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;
import model.PoiEventInfo;
import org.jgrapht.graph.DirectedPseudograph;

public class LlmEvidencePathExtractor {
   private static final double SCORE_EPSILON = 1.0E-9;
   private static final int DEFAULT_MAX_EVIDENCE_SEARCH_STATES_PER_PATH = 3000;
   private static final double NEAR_DUPLICATE_OVERLAP = 0.70;
   private static final double OVERLAP_PENALTY_WEIGHT = 1.0;

   public LlmEvidencePathResult extractPath(
      DirectedPseudograph<EntityNode, EventEdge> backJg, EntityNode entry, PoiEventInfo poiEventInfo
   ) {
      return extractPaths(backJg, entry, poiEventInfo, 1);
   }

   public LlmEvidencePathResult extractPaths(
      DirectedPseudograph<EntityNode, EventEdge> backJg, EntityNode entry, PoiEventInfo poiEventInfo, int maxPaths
   ) {
      return extractPaths(backJg, entry, poiEventInfo, maxPaths, DEFAULT_MAX_EVIDENCE_SEARCH_STATES_PER_PATH);
   }

   public LlmEvidencePathResult extractPaths(
      DirectedPseudograph<EntityNode, EventEdge> backJg,
      EntityNode entry,
      PoiEventInfo poiEventInfo,
      int maxPaths,
      int maxEvidenceSearchStatesPerPath
   ) {
      if (maxPaths <= 0) {
         throw new IllegalArgumentException("maxPaths must be positive.");
      }
      if (maxEvidenceSearchStatesPerPath <= 0) {
         throw new IllegalArgumentException("maxEvidenceSearchStatesPerPath must be positive.");
      }

      int maxExpandedStates = calculateMaxExpandedStates(maxPaths, maxEvidenceSearchStatesPerPath);

      if (backJg == null || entry == null || poiEventInfo == null) {
         return unmatched(
            entry, null, "Missing graph, entry, or POI event information.", LlmEvidencePathSearchStatus.UNAVAILABLE, 0, maxExpandedStates
         );
      }

      EventEdge poiEdge = findPoiEdge(backJg, poiEventInfo);
      if (poiEdge == null) {
         return unmatched(entry, null, "POI edge was not found in backJg.", LlmEvidencePathSearchStatus.UNAVAILABLE, 0, maxExpandedStates);
      }

      PriorityQueue<PathState> queue = new PriorityQueue<>(
         Comparator.comparingDouble(PathState::getPriorityScore)
            .reversed()
            .thenComparingInt(PathState::getDepth)
            .thenComparing(PathState::getEdgeKey)
      );
      List<EntityNode> initialNodes = new ArrayList<>();
      initialNodes.add(entry);
      queue.offer(new PathState(entry, initialNodes, new ArrayList<EventEdge>(), 0.0, heuristic(entry)));

      List<PathBuildResult> candidates = new ArrayList<>();
      Set<String> seenPathKeys = new HashSet<>();
      int expandedStates = 0;
      while (!queue.isEmpty() && expandedStates < maxExpandedStates) {
         PathState currentState = queue.poll();
         expandedStates++;

         for (EventEdge outEdge : selectOutgoingEdges(backJg, currentState.currentNode)) {
            if (sameEdge(outEdge, poiEdge)) {
               PathBuildResult candidate = buildPathGraph(currentState, poiEdge);
               if (seenPathKeys.add(candidate.edgeKey)) {
                  candidates.add(candidate);
               }
               continue;
            }

            EntityNode next = outEdge.getSink();
            if (containsNode(currentState.orderedNodes, next.getId())) {
               continue;
            }

            double nextPathScore = currentState.pathScore + edgeContribution(outEdge);
            queue.offer(currentState.extend(outEdge, nextPathScore, heuristic(next)));
         }
      }

      boolean searchTruncated = !queue.isEmpty();
      int pathProbeLimit = Math.max(maxPaths, 2);
      List<LlmEvidencePath> probedPaths = selectDiversePaths(candidates, entry, poiEdge, pathProbeLimit);
      List<LlmEvidencePath> selectedPaths = new ArrayList<>(probedPaths.subList(0, Math.min(maxPaths, probedPaths.size())));
      if (selectedPaths.isEmpty()) {
         String message = "No path from entry to POI edge was found.";
         if (searchTruncated) {
            message += " Search reached the evidence path state limit.";
         }
         return unmatched(
            entry,
            poiEdge,
            message,
            searchTruncated ? LlmEvidencePathSearchStatus.TRUNCATED : LlmEvidencePathSearchStatus.NO_PATH,
            expandedStates,
            maxExpandedStates
         );
      }

      String message = "Matched " + selectedPaths.size() + " differentiated evidence path(s) from entry to POI.";
      if (searchTruncated) {
         message += " Search reached the evidence path state limit; returned the paths found so far.";
      }
      LlmEvidencePathSearchStatus searchStatus = searchTruncated
         ? LlmEvidencePathSearchStatus.TRUNCATED
         : probedPaths.size() == 1
            ? LlmEvidencePathSearchStatus.EXHAUSTIVE_SINGLE_PATH
            : LlmEvidencePathSearchStatus.EXHAUSTIVE_MULTIPLE_PATHS;
      return new LlmEvidencePathResult(
         entry, poiEdge, true, message, selectedPaths, searchStatus, expandedStates, maxExpandedStates
      );
   }

   private static int calculateMaxExpandedStates(int maxPaths, int maxEvidenceSearchStatesPerPath) {
      try {
         return Math.multiplyExact(maxPaths, maxEvidenceSearchStatesPerPath);
      } catch (ArithmeticException ex) {
         throw new IllegalArgumentException("Evidence path search state limit exceeds the integer range.", ex);
      }
   }

   private static LlmEvidencePathResult unmatched(
      EntityNode entry,
      EventEdge poiEdge,
      String message,
      LlmEvidencePathSearchStatus searchStatus,
      int expandedStates,
      int searchStateLimit
   ) {
      return new LlmEvidencePathResult(
         entry,
         poiEdge,
         false,
         message,
         Collections.<LlmEvidencePath>emptyList(),
         searchStatus,
         expandedStates,
         searchStateLimit
      );
   }

   private List<LlmEvidencePath> selectDiversePaths(
      List<PathBuildResult> candidates, EntityNode entry, EventEdge poiEdge, int maxPaths
   ) {
      List<PathBuildResult> remaining = new ArrayList<>(candidates);
      remaining.sort(
         Comparator.comparingDouble(PathBuildResult::getBaseScore).reversed().thenComparing(PathBuildResult::getEdgeKey)
      );

      List<LlmEvidencePath> selected = new ArrayList<>();
      while (!remaining.isEmpty() && selected.size() < maxPaths) {
         PathBuildResult best = null;
         double bestSelectionScore = Double.NEGATIVE_INFINITY;
         double bestOverlap = 0.0;

         for (PathBuildResult candidate : remaining) {
            double maxOverlap = maxOverlap(candidate, selected, entry, poiEdge);
            if (maxOverlap >= NEAR_DUPLICATE_OVERLAP) {
               continue;
            }

            double selectionScore = candidate.baseScore - OVERLAP_PENALTY_WEIGHT * maxOverlap;
            if (best == null
               || Double.compare(selectionScore, bestSelectionScore) > 0
               || (Double.compare(selectionScore, bestSelectionScore) == 0 && candidate.edgeKey.compareTo(best.edgeKey) < 0)) {
               best = candidate;
               bestSelectionScore = selectionScore;
               bestOverlap = maxOverlap;
            }
         }

         if (best == null) {
            break;
         }

         selected.add(
            new LlmEvidencePath(
               selected.size() + 1,
               best.baseScore,
               bestSelectionScore,
               bestOverlap,
               best.graph,
               best.orderedNodes,
               best.orderedEdges
            )
         );
         remaining.remove(best);
      }

      return selected;
   }

   private double maxOverlap(
      PathBuildResult candidate, List<LlmEvidencePath> selected, EntityNode entry, EventEdge poiEdge
   ) {
      double maxOverlap = 0.0;
      for (LlmEvidencePath selectedPath : selected) {
         double nodeOverlap = jaccard(
            evidenceNodeIds(candidate.orderedNodes, entry, poiEdge),
            evidenceNodeIds(selectedPath.getOrderedNodes(), entry, poiEdge)
         );
         double edgeOverlap = jaccard(
            evidenceEdgeIds(candidate.orderedEdges, poiEdge), evidenceEdgeIds(selectedPath.getOrderedEdges(), poiEdge)
         );
         maxOverlap = Math.max(maxOverlap, Math.max(nodeOverlap, edgeOverlap));
      }
      return maxOverlap;
   }

   private Set<Long> evidenceNodeIds(List<EntityNode> nodes, EntityNode entry, EventEdge poiEdge) {
      Set<Long> ids = new LinkedHashSet<>();
      long entryId = entry == null ? Long.MIN_VALUE : entry.getId();
      long poiSourceId = poiEdge == null || poiEdge.getSource() == null ? Long.MIN_VALUE : poiEdge.getSource().getId();
      long poiSinkId = poiEdge == null || poiEdge.getSink() == null ? Long.MIN_VALUE : poiEdge.getSink().getId();
      for (EntityNode node : nodes) {
         if (node != null && node.getId() != entryId && node.getId() != poiSourceId && node.getId() != poiSinkId) {
            ids.add(node.getId());
         }
      }
      return ids;
   }

   private Set<Long> evidenceEdgeIds(List<EventEdge> edges, EventEdge poiEdge) {
      Set<Long> ids = new LinkedHashSet<>();
      for (EventEdge edge : edges) {
         if (!sameEdge(edge, poiEdge)) {
            ids.add(edge.getID());
         }
      }
      return ids;
   }

   private static double jaccard(Set<Long> left, Set<Long> right) {
      if (left.isEmpty() && right.isEmpty()) {
         return 0.0;
      }

      Set<Long> union = new HashSet<>(left);
      union.addAll(right);
      Set<Long> intersection = new HashSet<>(left);
      intersection.retainAll(right);
      return (double)intersection.size() / union.size();
   }

   private EventEdge findPoiEdge(DirectedPseudograph<EntityNode, EventEdge> backJg, PoiEventInfo poiEventInfo) {
      for (EventEdge edge : backJg.edgeSet()) {
         if (poiEventInfo.matches(edge)) {
            return edge;
         }
      }

      for (EventEdge edge : backJg.edgeSet()) {
         if (poiEventInfo.matchesRelaxed(edge)) {
            return edge;
         }
      }

      return null;
   }

   private List<EventEdge> selectOutgoingEdges(DirectedPseudograph<EntityNode, EventEdge> graph, EntityNode current) {
      List<EventEdge> edges = new ArrayList<>(graph.outgoingEdgesOf(current));
      edges.sort(LlmEvidencePathExtractor::compareEdges);
      return edges;
   }

   private static int compareEdges(EventEdge left, EventEdge right) {
      int weightCompare = Double.compare(right.weight, left.weight);
      if (weightCompare != 0) {
         return weightCompare;
      }

      if (left.getEndTime() != null && right.getEndTime() != null) {
         int endTimeCompare = right.getEndTime().compareTo(left.getEndTime());
         if (endTimeCompare != 0) {
            return endTimeCompare;
         }
      }

      return Long.compare(left.getID(), right.getID());
   }

   private PathBuildResult buildPathGraph(PathState state, EventEdge poiEdge) {
      DirectedPseudograph<EntityNode, EventEdge> pathGraph = new DirectedPseudograph(EventEdge.class);
      List<EventEdge> orderedEdges = new ArrayList<>(state.orderedEdges);
      List<EntityNode> orderedNodes = new ArrayList<>(state.orderedNodes);

      for (EventEdge edge : orderedEdges) {
         addEdge(pathGraph, edge);
      }

      addEdge(pathGraph, poiEdge);
      orderedEdges.add(poiEdge);
      orderedNodes.add(poiEdge.getSink());
      return new PathBuildResult(pathGraph, orderedNodes, orderedEdges, state.getPriorityScore());
   }

   private static double edgeContribution(EventEdge edge) {
      return Math.log(Math.max(edge.weight, SCORE_EPSILON));
   }

   private static double heuristic(EntityNode node) {
      return Math.log(Math.max(node.getReputation(), SCORE_EPSILON));
   }

   private static boolean containsNode(List<EntityNode> orderedNodes, long nodeId) {
      for (EntityNode node : orderedNodes) {
         if (node.getId() == nodeId) {
            return true;
         }
      }

      return false;
   }

   private void addEdge(DirectedPseudograph<EntityNode, EventEdge> graph, EventEdge edge) {
      if (!graph.containsVertex(edge.getSource())) {
         graph.addVertex(edge.getSource());
      }

      if (!graph.containsVertex(edge.getSink())) {
         graph.addVertex(edge.getSink());
      }

      graph.addEdge(edge.getSource(), edge.getSink(), edge);
   }

   private static boolean sameEdge(EventEdge left, EventEdge right) {
      return left != null && right != null && left.equals(right);
   }

   private static class PathState {
      private final EntityNode currentNode;
      private final List<EntityNode> orderedNodes;
      private final List<EventEdge> orderedEdges;
      private final double pathScore;
      private final double heuristicScore;

      private PathState(
         EntityNode currentNode, List<EntityNode> orderedNodes, List<EventEdge> orderedEdges, double pathScore, double heuristicScore
      ) {
         this.currentNode = currentNode;
         this.orderedNodes = orderedNodes;
         this.orderedEdges = orderedEdges;
         this.pathScore = pathScore;
         this.heuristicScore = heuristicScore;
      }

      private PathState extend(EventEdge edge, double nextPathScore, double nextHeuristicScore) {
         List<EntityNode> nextNodes = new ArrayList<>(this.orderedNodes);
         nextNodes.add(edge.getSink());
         List<EventEdge> nextEdges = new ArrayList<>(this.orderedEdges);
         nextEdges.add(edge);
         return new PathState(edge.getSink(), nextNodes, nextEdges, nextPathScore, nextHeuristicScore);
      }

      private double getPriorityScore() {
         return this.pathScore + this.heuristicScore;
      }

      private int getDepth() {
         return this.orderedEdges.size();
      }

      private String getEdgeKey() {
         return edgeKey(this.orderedEdges);
      }
   }

   private static class PathBuildResult {
      private final DirectedPseudograph<EntityNode, EventEdge> graph;
      private final List<EntityNode> orderedNodes;
      private final List<EventEdge> orderedEdges;
      private final double baseScore;
      private final String edgeKey;

      private PathBuildResult(
         DirectedPseudograph<EntityNode, EventEdge> graph, List<EntityNode> orderedNodes, List<EventEdge> orderedEdges, double baseScore
      ) {
         this.graph = graph;
         this.orderedNodes = orderedNodes;
         this.orderedEdges = orderedEdges;
         this.baseScore = baseScore;
         this.edgeKey = edgeKey(orderedEdges);
      }

      private double getBaseScore() {
         return this.baseScore;
      }

      private String getEdgeKey() {
         return this.edgeKey;
      }
   }

   private static String edgeKey(List<EventEdge> edges) {
      StringBuilder builder = new StringBuilder();
      for (EventEdge edge : edges) {
         if (builder.length() > 0) {
            builder.append(',');
         }
         builder.append(edge.getID());
      }
      return builder.toString();
   }
}
