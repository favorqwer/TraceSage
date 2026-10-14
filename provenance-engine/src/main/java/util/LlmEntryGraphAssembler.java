package util;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

public class LlmEntryGraphAssembler {
   public LlmEntryGraphAssemblyResult assemble(
      DirectedPseudograph<EntityNode, EventEdge> forwardGraph,
      DirectedPseudograph<EntityNode, EventEdge> backwardGraph,
      EntityNode entryNode,
      EntityNode anomalyNode
   ) {
      List<EntityNode> entryNodes = new ArrayList<>();
      if (entryNode != null) {
         entryNodes.add(entryNode);
      }
      return assemble(forwardGraph, backwardGraph, entryNodes, anomalyNode);
   }

   public LlmEntryGraphAssemblyResult assemble(
      DirectedPseudograph<EntityNode, EventEdge> forwardGraph,
      DirectedPseudograph<EntityNode, EventEdge> backwardGraph,
      List<EntityNode> entryNodes,
      EntityNode anomalyNode
   ) {
      DirectedPseudograph<EntityNode, EventEdge> safeForward = forwardGraph == null ? new DirectedPseudograph(EventEdge.class) : forwardGraph;
      DirectedPseudograph<EntityNode, EventEdge> safeBackward = backwardGraph == null ? new DirectedPseudograph(EventEdge.class) : backwardGraph;
      DirectedPseudograph<EntityNode, EventEdge> rawIntersect = intersectGraphs(safeBackward, safeForward);
      ComponentSelectionResult filteredIntersectSelection = selectIntersectComponents(rawIntersect, entryNodes, anomalyNode);
      DirectedPseudograph<EntityNode, EventEdge> filteredIntersect = filteredIntersectSelection.graph;
      return new LlmEntryGraphAssemblyResult(
         rawIntersect,
         filteredIntersect,
         filteredIntersectSelection.componentCount,
         filteredIntersectSelection.matched,
         filteredIntersectSelection.multipleMatches
      );
   }

   private DirectedPseudograph<EntityNode, EventEdge> intersectGraphs(
      DirectedPseudograph<EntityNode, EventEdge> backwardGraph, DirectedPseudograph<EntityNode, EventEdge> forwardGraph
   ) {
      DirectedPseudograph<EntityNode, EventEdge> intersect = new DirectedPseudograph(EventEdge.class);
      Set<String> forwardEdgeSignatures = new LinkedHashSet<>();
      for (EventEdge edge : forwardGraph.edgeSet()) {
         forwardEdgeSignatures.add(IterateGraph.convertEdgeToString(edge));
      }

      Map<Long, EntityNode> backwardNodeMap = mapNodesById(backwardGraph);
      for (EventEdge edge : backwardGraph.edgeSet()) {
         if (!forwardEdgeSignatures.contains(IterateGraph.convertEdgeToString(edge))) {
            continue;
         }

         EntityNode src = backwardNodeMap.get(edge.getSource().getId());
         EntityNode dst = backwardNodeMap.get(edge.getSink().getId());
         if (!intersect.containsVertex(src)) {
            intersect.addVertex(src);
         }

         if (!intersect.containsVertex(dst)) {
            intersect.addVertex(dst);
         }

         intersect.addEdge(src, dst, edge);
      }

      return intersect;
   }

   private ComponentSelectionResult selectIntersectComponents(
      DirectedPseudograph<EntityNode, EventEdge> rawIntersect, List<EntityNode> entryNodes, EntityNode anomalyNode
   ) {
      List<Set<EntityNode>> components = collectUndirectedComponents(rawIntersect);
      DirectedPseudograph<EntityNode, EventEdge> filtered = new DirectedPseudograph(EventEdge.class);
      boolean matched = false;
      boolean multipleMatches = false;

      for (Set<EntityNode> component : components) {
         boolean hasEntry = containsAnyNodeId(component, entryNodes);
         boolean hasAnomaly = containsNodeId(component, anomalyNode);
         if (!hasEntry || !hasAnomaly) {
            continue;
         }

         if (matched) {
            multipleMatches = true;
         }
         filtered = unionGraphs(filtered, inducedSubgraph(rawIntersect, component));
         matched = true;
      }

      return new ComponentSelectionResult(filtered, components.size(), matched, multipleMatches);
   }

   private DirectedPseudograph<EntityNode, EventEdge> inducedSubgraph(
      DirectedPseudograph<EntityNode, EventEdge> graph, Set<EntityNode> component
   ) {
      DirectedPseudograph<EntityNode, EventEdge> subgraph = new DirectedPseudograph(EventEdge.class);
      Set<Long> componentIds = toNodeIdSet(component);

      for (EntityNode node : component) {
         if (!subgraph.containsVertex(node)) {
            subgraph.addVertex(node);
         }
      }

      for (EventEdge edge : graph.edgeSet()) {
         if (!componentIds.contains(edge.getSource().getId()) || !componentIds.contains(edge.getSink().getId())) {
            continue;
         }

         if (!subgraph.containsVertex(edge.getSource())) {
            subgraph.addVertex(edge.getSource());
         }

         if (!subgraph.containsVertex(edge.getSink())) {
            subgraph.addVertex(edge.getSink());
         }

         subgraph.addEdge(edge.getSource(), edge.getSink(), edge);
      }

      return subgraph;
   }

   private List<Set<EntityNode>> collectUndirectedComponents(DirectedPseudograph<EntityNode, EventEdge> graph) {
      List<Set<EntityNode>> components = new ArrayList<>();
      Set<Long> visited = new LinkedHashSet<>();

      for (EntityNode node : graph.vertexSet()) {
         if (!visited.add(node.getId())) {
            continue;
         }

         Set<EntityNode> component = new LinkedHashSet<>();
         Queue<EntityNode> queue = new ArrayDeque<>();
         queue.offer(node);
         component.add(node);

         while (!queue.isEmpty()) {
            EntityNode current = queue.poll();
            for (EventEdge edge : graph.outgoingEdgesOf(current)) {
               EntityNode next = edge.getSink();
               if (visited.add(next.getId())) {
                  queue.offer(next);
               }
               component.add(next);
            }

            for (EventEdge edge : graph.incomingEdgesOf(current)) {
               EntityNode next = edge.getSource();
               if (visited.add(next.getId())) {
                  queue.offer(next);
               }
               component.add(next);
            }
         }

         components.add(component);
      }

      return components;
   }

   private boolean containsNodeId(Set<EntityNode> component, EntityNode targetNode) {
      if (targetNode == null) {
         return false;
      }

      long targetId = targetNode.getId();
      for (EntityNode node : component) {
         if (node.getId() == targetId) {
            return true;
         }
      }

      return false;
   }

   private boolean containsAnyNodeId(Set<EntityNode> component, List<EntityNode> targetNodes) {
      if (targetNodes == null || targetNodes.isEmpty()) {
         return false;
      }
      for (EntityNode targetNode : targetNodes) {
         if (containsNodeId(component, targetNode)) {
            return true;
         }
      }
      return false;
   }

   private DirectedPseudograph<EntityNode, EventEdge> unionGraphs(
      DirectedPseudograph<EntityNode, EventEdge> left,
      DirectedPseudograph<EntityNode, EventEdge> right
   ) {
      DirectedPseudograph<EntityNode, EventEdge> union = new DirectedPseudograph(EventEdge.class);
      addGraph(union, left);
      addGraph(union, right);
      return union;
   }

   private void addGraph(DirectedPseudograph<EntityNode, EventEdge> target, DirectedPseudograph<EntityNode, EventEdge> source) {
      if (source == null) {
         return;
      }
      for (EntityNode node : source.vertexSet()) {
         if (!target.containsVertex(node)) {
            target.addVertex(node);
         }
      }
      for (EventEdge edge : source.edgeSet()) {
         if (!target.containsVertex(edge.getSource())) {
            target.addVertex(edge.getSource());
         }
         if (!target.containsVertex(edge.getSink())) {
            target.addVertex(edge.getSink());
         }
         target.addEdge(edge.getSource(), edge.getSink(), edge);
      }
   }

   private Map<Long, EntityNode> mapNodesById(DirectedPseudograph<EntityNode, EventEdge> graph) {
      Map<Long, EntityNode> nodeMap = new LinkedHashMap<>();
      for (EntityNode node : graph.vertexSet()) {
         nodeMap.put(node.getId(), node);
      }

      return nodeMap;
   }

   private Set<Long> toNodeIdSet(Set<EntityNode> nodes) {
      Set<Long> ids = new LinkedHashSet<>();
      for (EntityNode node : nodes) {
         ids.add(node.getId());
      }

      return ids;
   }

   private static final class ComponentSelectionResult {
      private final DirectedPseudograph<EntityNode, EventEdge> graph;
      private final int componentCount;
      private final boolean matched;
      private final boolean multipleMatches;

      private ComponentSelectionResult(
         DirectedPseudograph<EntityNode, EventEdge> graph, int componentCount, boolean matched, boolean multipleMatches
      ) {
         this.graph = graph;
         this.componentCount = componentCount;
         this.matched = matched;
         this.multipleMatches = multipleMatches;
      }
   }

   public static final class LlmEntryGraphAssemblyResult {
      private final DirectedPseudograph<EntityNode, EventEdge> rawIntersect;
      private final DirectedPseudograph<EntityNode, EventEdge> filteredIntersect;
      private final int rawIntersectComponentCount;
      private final boolean intersectMatchFound;
      private final boolean multipleIntersectMatches;

      private LlmEntryGraphAssemblyResult(
         DirectedPseudograph<EntityNode, EventEdge> rawIntersect,
         DirectedPseudograph<EntityNode, EventEdge> filteredIntersect,
         int rawIntersectComponentCount,
         boolean intersectMatchFound,
         boolean multipleIntersectMatches
      ) {
         this.rawIntersect = rawIntersect;
         this.filteredIntersect = filteredIntersect;
         this.rawIntersectComponentCount = rawIntersectComponentCount;
         this.intersectMatchFound = intersectMatchFound;
         this.multipleIntersectMatches = multipleIntersectMatches;
      }

      public DirectedPseudograph<EntityNode, EventEdge> getRawIntersect() {
         return this.rawIntersect;
      }

      public DirectedPseudograph<EntityNode, EventEdge> getFilteredIntersect() {
         return this.filteredIntersect;
      }

      public int getRawIntersectComponentCount() {
         return this.rawIntersectComponentCount;
      }

      public boolean isIntersectMatchFound() {
         return this.intersectMatchFound;
      }

      public boolean isMultipleIntersectMatches() {
         return this.multipleIntersectMatches;
      }
   }
}
