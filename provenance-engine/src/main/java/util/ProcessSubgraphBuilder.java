package util;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

public final class ProcessSubgraphBuilder {
   private static final String[] PRUNING_REASONS = {
      "UPSTREAM_HIGH_DEGREE", "DOWNSTREAM_HIGH_DEGREE",
      "UPSTREAM_ENTRY_BOUNDARY", "DOWNSTREAM_POI_BOUNDARY",
      "UPSTREAM_MAX_DEPTH", "DOWNSTREAM_MAX_DEPTH",
      "UPSTREAM_CYCLE", "DOWNSTREAM_CYCLE",
      "UPSTREAM_NO_PROCESS_EDGE", "DOWNSTREAM_NO_PROCESS_EDGE"
   };
   private static final String[] EDGE_TYPES = {
      "process->process", "process->file", "file->process", "process->network", "network->process"
   };
   private final SubgraphConfig config;

   public ProcessSubgraphBuilder(SubgraphConfig config) {
      this.config = config;
   }

   public ProcessSubgraphBuildResult build(DirectedPseudograph<EntityNode, EventEdge> graph, Set<EntityNode> entryNodes, Set<EntityNode> poiNodes) {
      DirectedPseudograph<EntityNode, EventEdge> safeGraph = graph == null ? new DirectedPseudograph(EventEdge.class) : graph;
      Map<Long, EntityNode> processes = processNodes(safeGraph);
      Map<EventEdge, Long> owners = assignOwners(safeGraph);
      validateOwnerPartition(safeGraph, owners);
      Map<Long, List<EventEdge>> incomingProcessEdges = new HashMap<>();
      Map<Long, List<EventEdge>> outgoingProcessEdges = new HashMap<>();
      indexProcessEdges(safeGraph, incomingProcessEdges, outgoingProcessEdges);
      int upstreamThreshold = degreeThreshold(incomingProcessEdges, processes.keySet());
      int downstreamThreshold = degreeThreshold(outgoingProcessEdges, processes.keySet());
      Set<Long> entryAnchors = projectProcessAnchors(safeGraph, entryNodes);
      Set<Long> poiAnchors = projectProcessAnchors(safeGraph, poiNodes);
      Set<Long> entryAdjacent = adjacentProcesses(safeGraph, entryAnchors);
      Set<Long> poiAdjacent = adjacentProcesses(safeGraph, poiAnchors);
      Map<Long, ProcessSubgraph> subgraphs = new LinkedHashMap<>();
      Map<String, Integer> pruningHitCounts = emptyPruningCounts();
      List<EntityNode> orderedProcesses = new ArrayList<>(processes.values());
      Collections.sort(orderedProcesses, Comparator.comparingLong(EntityNode::getId));
      for (EntityNode root : orderedProcesses) {
         subgraphs.put(root.getId(), buildOne(safeGraph, root, owners, incomingProcessEdges, outgoingProcessEdges, entryAnchors,
            entryAdjacent, poiAnchors, poiAdjacent, upstreamThreshold, downstreamThreshold, pruningHitCounts));
      }
      return new ProcessSubgraphBuildResult(subgraphs, owners, upstreamThreshold, downstreamThreshold, pruningHitCounts,
         pruningSubgraphCounts(subgraphs), edgeTypeCounts(safeGraph), depthCounts(subgraphs, true), depthCounts(subgraphs, false),
         maxDepthRootIds(subgraphs, true), maxDepthRootIds(subgraphs, false), degreeMap(incomingProcessEdges, orderedProcesses),
         degreeMap(outgoingProcessEdges, orderedProcesses), processLabels(orderedProcesses));
   }

   private ProcessSubgraph buildOne(DirectedPseudograph<EntityNode, EventEdge> graph, EntityNode root, Map<EventEdge, Long> owners,
      Map<Long, List<EventEdge>> incomingProcessEdges, Map<Long, List<EventEdge>> outgoingProcessEdges, Set<Long> entryAnchors,
      Set<Long> entryAdjacent, Set<Long> poiAnchors, Set<Long> poiAdjacent, int upstreamThreshold, int downstreamThreshold,
      Map<String, Integer> pruningHitCounts) {
      Set<EventEdge> included = new LinkedHashSet<>();
      Set<Long> visibleProcesses = new LinkedHashSet<>();
      Set<Long> upstreamProcesses = new LinkedHashSet<>();
      Set<Long> downstreamProcesses = new LinkedHashSet<>();
      Map<Long, Integer> upstreamProcessDepths = new LinkedHashMap<>();
      Map<Long, Integer> downstreamProcessDepths = new LinkedHashMap<>();
      Set<String> boundaryReasons = new LinkedHashSet<>();
      includeProcessLocalGraph(graph, root, included, visibleProcesses);
      upstreamProcessDepths.put(root.getId(), 0);
      downstreamProcessDepths.put(root.getId(), 0);
      expand(graph, root, true, included, visibleProcesses, upstreamProcesses, boundaryReasons, incomingProcessEdges, outgoingProcessEdges,
         entryAnchors, entryAdjacent, poiAnchors, poiAdjacent, upstreamThreshold, downstreamThreshold, pruningHitCounts, upstreamProcessDepths);
      expand(graph, root, false, included, visibleProcesses, downstreamProcesses, boundaryReasons, incomingProcessEdges, outgoingProcessEdges,
         entryAnchors, entryAdjacent, poiAnchors, poiAdjacent, upstreamThreshold, downstreamThreshold, pruningHitCounts, downstreamProcessDepths);
      Set<EventEdge> owned = new LinkedHashSet<>();
      for (EventEdge edge : included) {
         Long ownerId = owners.get(edge);
         if (ownerId != null && ownerId.longValue() == root.getId()) owned.add(edge);
      }
      Set<EventEdge> context = new LinkedHashSet<>(included);
      context.removeAll(owned);
      return new ProcessSubgraph(root, owned, context, upstreamProcesses, downstreamProcesses, upstreamProcessDepths, downstreamProcessDepths,
         boundaryReasons);
   }

   private void expand(DirectedPseudograph<EntityNode, EventEdge> graph, EntityNode root, boolean upstream, Set<EventEdge> included,
      Set<Long> visibleProcesses, Set<Long> expandedDirection, Set<String> boundaryReasons, Map<Long, List<EventEdge>> incomingProcessEdges,
      Map<Long, List<EventEdge>> outgoingProcessEdges, Set<Long> entryAnchors, Set<Long> entryAdjacent, Set<Long> poiAnchors,
      Set<Long> poiAdjacent, int upstreamThreshold, int downstreamThreshold, Map<String, Integer> pruningHitCounts,
      Map<Long, Integer> processDepths) {
      Deque<ProcessDepth> queue = new ArrayDeque<>();
      Set<Long> expanded = new HashSet<>();
      queue.add(new ProcessDepth(root, 0));
      while (!queue.isEmpty()) {
         ProcessDepth current = queue.removeFirst();
         if (!expanded.add(current.process.getId())) {
            recordPruning(boundaryReasons, pruningHitCounts, upstream ? "UPSTREAM_CYCLE" : "DOWNSTREAM_CYCLE");
            continue;
         }
         List<EventEdge> processEdges = upstream ? incomingProcessEdges.get(current.process.getId()) : outgoingProcessEdges.get(current.process.getId());
         int threshold = upstream ? upstreamThreshold : downstreamThreshold;
         if (processEdges != null && processEdges.size() > threshold) {
            recordPruning(boundaryReasons, pruningHitCounts, upstream ? "UPSTREAM_HIGH_DEGREE" : "DOWNSTREAM_HIGH_DEGREE");
            continue;
         }
         boolean isAnchorBoundary = upstream
            ? entryAnchors.contains(current.process.getId()) || entryAdjacent.contains(current.process.getId())
            : poiAnchors.contains(current.process.getId()) || poiAdjacent.contains(current.process.getId());
         if (isAnchorBoundary) {
            recordPruning(boundaryReasons, pruningHitCounts, upstream ? "UPSTREAM_ENTRY_BOUNDARY" : "DOWNSTREAM_POI_BOUNDARY");
            continue;
         }
         int maxDepth = upstream ? this.config.getMaxUpstreamDepth() : this.config.getMaxDownstreamDepth();
         if (current.depth >= maxDepth) {
            recordPruning(boundaryReasons, pruningHitCounts, upstream ? "UPSTREAM_MAX_DEPTH" : "DOWNSTREAM_MAX_DEPTH");
            continue;
         }
         boolean hadRealProcessEdge = false;
         if (processEdges != null) {
            for (EventEdge edge : processEdges) {
               EntityNode next = upstream ? edge.getSource() : edge.getSink();
               if (next == null || next.getP() == null) continue;
               hadRealProcessEdge = true;
               if (expanded.contains(next.getId())) {
                  recordPruning(boundaryReasons, pruningHitCounts, upstream ? "UPSTREAM_CYCLE" : "DOWNSTREAM_CYCLE");
                  continue;
               }
               includeProcessLocalGraph(graph, next, included, visibleProcesses);
               expandedDirection.add(next.getId());
               int nextDepth = current.depth + 1;
               Integer knownDepth = processDepths.get(next.getId());
               if (knownDepth == null || nextDepth < knownDepth.intValue()) processDepths.put(next.getId(), nextDepth);
               boolean stopAtAnchor = upstream
                  ? entryAnchors.contains(next.getId()) || entryAdjacent.contains(next.getId())
                  : poiAnchors.contains(next.getId()) || poiAdjacent.contains(next.getId());
               if (stopAtAnchor) {
                  recordPruning(boundaryReasons, pruningHitCounts, upstream ? "UPSTREAM_ENTRY_BOUNDARY" : "DOWNSTREAM_POI_BOUNDARY");
                  continue;
               }
               queue.addLast(new ProcessDepth(next, current.depth + 1));
            }
         }
         if (!hadRealProcessEdge) recordPruning(boundaryReasons, pruningHitCounts,
            upstream ? "UPSTREAM_NO_PROCESS_EDGE" : "DOWNSTREAM_NO_PROCESS_EDGE");
      }
   }

   private static void recordPruning(Set<String> boundaryReasons, Map<String, Integer> pruningHitCounts, String reason) {
      boundaryReasons.add(reason);
      pruningHitCounts.put(reason, pruningHitCounts.get(reason) + 1);
   }

   private static Map<String, Integer> emptyPruningCounts() {
      Map<String, Integer> counts = new LinkedHashMap<>();
      for (String reason : PRUNING_REASONS) counts.put(reason, 0);
      return counts;
   }

   private static Map<String, Integer> pruningSubgraphCounts(Map<Long, ProcessSubgraph> subgraphs) {
      Map<String, Integer> counts = emptyPruningCounts();
      for (ProcessSubgraph subgraph : subgraphs.values()) {
         for (String reason : subgraph.getBoundaryReasons()) counts.put(reason, counts.get(reason) + 1);
      }
      return counts;
   }

   private static Map<String, Integer> edgeTypeCounts(DirectedPseudograph<EntityNode, EventEdge> graph) {
      Map<String, Integer> counts = new LinkedHashMap<>();
      for (String type : EDGE_TYPES) counts.put(type, 0);
      for (EventEdge edge : graph.edgeSet()) {
         String type = edgeType(edge);
         counts.put(type, counts.get(type) + 1);
      }
      return counts;
   }

   private static String edgeType(EventEdge edge) {
      EntityNode source = edge.getSource();
      EntityNode sink = edge.getSink();
      if (isProcess(source) && isProcess(sink)) return "process->process";
      if (isProcess(source) && isFile(sink)) return "process->file";
      if (isFile(source) && isProcess(sink)) return "file->process";
      if (isProcess(source) && isNetwork(sink)) return "process->network";
      if (isNetwork(source) && isProcess(sink)) return "network->process";
      throw new IllegalArgumentException("Unsupported edge in process-subgraph base graph: edgeId=" + edge.getID());
   }

   private static Map<Integer, Integer> depthCounts(Map<Long, ProcessSubgraph> subgraphs, boolean upstream) {
      Map<Integer, Integer> counts = new LinkedHashMap<>();
      for (ProcessSubgraph subgraph : subgraphs.values()) {
         Map<Long, Integer> depths = upstream ? subgraph.getUpstreamProcessDepths() : subgraph.getDownstreamProcessDepths();
         for (Integer depth : depths.values()) counts.put(depth, counts.containsKey(depth) ? counts.get(depth) + 1 : 1);
      }
      return counts;
   }

   private static List<Long> maxDepthRootIds(Map<Long, ProcessSubgraph> subgraphs, boolean upstream) {
      List<Long> rootIds = new ArrayList<>();
      String reason = upstream ? "UPSTREAM_MAX_DEPTH" : "DOWNSTREAM_MAX_DEPTH";
      for (ProcessSubgraph subgraph : subgraphs.values()) {
         if (subgraph.getBoundaryReasons().contains(reason)) rootIds.add(subgraph.getRootProcess().getId());
      }
      return rootIds;
   }

   private static Map<Long, Integer> degreeMap(Map<Long, List<EventEdge>> index, List<EntityNode> processes) {
      Map<Long, Integer> degrees = new LinkedHashMap<>();
      for (EntityNode process : processes) degrees.put(process.getId(), index.containsKey(process.getId()) ? index.get(process.getId()).size() : 0);
      return degrees;
   }

   private static Map<Long, String> processLabels(List<EntityNode> processes) {
      Map<Long, String> labels = new LinkedHashMap<>();
      for (EntityNode process : processes) {
         String executable = process.getP().getExePath();
         labels.put(process.getId(), executable == null || executable.isEmpty() ? process.getP().getName() : executable);
      }
      return labels;
   }

   private Map<EventEdge, Long> assignOwners(DirectedPseudograph<EntityNode, EventEdge> graph) {
      Map<EventEdge, Long> owners = new LinkedHashMap<>();
      for (EventEdge edge : graph.edgeSet()) {
         EntityNode source = edge.getSource();
         EntityNode sink = edge.getSink();
         EntityNode owner;
         if (isProcess(source) && isProcess(sink)) owner = sink;
         else if (isProcess(source) && (isFile(sink) || isNetwork(sink))) owner = source;
         else if ((isFile(source) || isNetwork(source)) && isProcess(sink)) owner = sink;
         else throw invalidEdge(edge);
         owners.put(edge, owner.getId());
      }
      return owners;
   }

   private IllegalArgumentException invalidEdge(EventEdge edge) {
      return new IllegalArgumentException("Unsupported edge in process-subgraph base graph: edgeId=" + edge.getID()
         + ", source=" + signature(edge.getSource()) + ", sink=" + signature(edge.getSink()));
   }

   private void validateOwnerPartition(DirectedPseudograph<EntityNode, EventEdge> graph, Map<EventEdge, Long> owners) {
      if (owners.size() != graph.edgeSet().size()) throw new IllegalStateException("Process-subgraph owner assignment does not cover G_base.");
      for (EventEdge edge : graph.edgeSet()) {
         if (!owners.containsKey(edge) || owners.get(edge) == null) throw new IllegalStateException("Missing owner for edge " + edge.getID());
      }
   }

   private void includeProcessLocalGraph(DirectedPseudograph<EntityNode, EventEdge> graph, EntityNode process, Set<EventEdge> included,
      Set<Long> visibleProcesses) {
      visibleProcesses.add(process.getId());
      for (EventEdge edge : graph.incomingEdgesOf(process)) {
         included.add(edge);
         if (isProcess(edge.getSource())) visibleProcesses.add(edge.getSource().getId());
      }
      for (EventEdge edge : graph.outgoingEdgesOf(process)) {
         included.add(edge);
         if (isProcess(edge.getSink())) visibleProcesses.add(edge.getSink().getId());
      }
   }

   private void indexProcessEdges(DirectedPseudograph<EntityNode, EventEdge> graph, Map<Long, List<EventEdge>> incoming, Map<Long, List<EventEdge>> outgoing) {
      for (EventEdge edge : graph.edgeSet()) {
         if (!isProcess(edge.getSource()) || !isProcess(edge.getSink())) continue;
         add(incoming, edge.getSink().getId(), edge);
         add(outgoing, edge.getSource().getId(), edge);
      }
   }

   private static void add(Map<Long, List<EventEdge>> index, long id, EventEdge edge) {
      List<EventEdge> edges = index.get(id);
      if (edges == null) { edges = new ArrayList<>(); index.put(id, edges); }
      edges.add(edge);
   }

   private int degreeThreshold(Map<Long, List<EventEdge>> degreeIndex, Set<Long> processIds) {
      List<Integer> degrees = new ArrayList<>();
      for (Long id : processIds) degrees.add(degreeIndex.containsKey(id) ? degreeIndex.get(id).size() : 0);
      Collections.sort(degrees);
      int quantileValue = degrees.isEmpty() ? 0 : degrees.get(Math.max(0, (int)Math.ceil(this.config.getProcessDegreeQuantile() * degrees.size()) - 1));
      return Math.min(this.config.getProcessDegreeMaximum(), Math.max(this.config.getProcessDegreeMinimum(), quantileValue));
   }

   private Set<Long> projectProcessAnchors(DirectedPseudograph<EntityNode, EventEdge> graph, Set<EntityNode> nodes) {
      Set<Long> anchors = new LinkedHashSet<>();
      if (nodes == null) return anchors;
      for (EntityNode node : nodes) {
         if (node == null) continue;
         if (isProcess(node)) anchors.add(node.getId());
         if (!graph.containsVertex(node)) continue;
         for (EventEdge edge : graph.incomingEdgesOf(node)) if (isProcess(edge.getSource())) anchors.add(edge.getSource().getId());
         for (EventEdge edge : graph.outgoingEdgesOf(node)) if (isProcess(edge.getSink())) anchors.add(edge.getSink().getId());
      }
      return anchors;
   }

   private Set<Long> adjacentProcesses(DirectedPseudograph<EntityNode, EventEdge> graph, Set<Long> anchors) {
      Set<Long> adjacent = new LinkedHashSet<>();
      for (EventEdge edge : graph.edgeSet()) {
         if (!isProcess(edge.getSource()) || !isProcess(edge.getSink())) continue;
         if (anchors.contains(edge.getSource().getId())) adjacent.add(edge.getSink().getId());
         if (anchors.contains(edge.getSink().getId())) adjacent.add(edge.getSource().getId());
      }
      adjacent.removeAll(anchors);
      return adjacent;
   }

   private Map<Long, EntityNode> processNodes(DirectedPseudograph<EntityNode, EventEdge> graph) {
      Map<Long, EntityNode> nodes = new LinkedHashMap<>();
      for (EntityNode node : graph.vertexSet()) if (isProcess(node)) nodes.put(node.getId(), node);
      return nodes;
   }

   private static boolean isProcess(EntityNode node) { return node != null && node.getP() != null; }
   private static boolean isFile(EntityNode node) { return node != null && node.getF() != null; }
   private static boolean isNetwork(EntityNode node) { return node != null && node.getN() != null; }
   private static String signature(EntityNode node) { return node == null ? "<null>" : node.getSignature(); }

   private static final class ProcessDepth {
      private final EntityNode process;
      private final int depth;
      private ProcessDepth(EntityNode process, int depth) { this.process = process; this.depth = depth; }
   }
}
