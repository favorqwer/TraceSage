package util;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

/** Graph operations whose membership semantics are based on canonical event identity. */
public final class GraphOperations {
   private GraphOperations() {
   }

   public static DirectedPseudograph<EntityNode, EventEdge> copy(DirectedPseudograph<EntityNode, EventEdge> source) {
      DirectedPseudograph<EntityNode, EventEdge> result = new DirectedPseudograph(EventEdge.class);
      if (source != null) {
         for (EntityNode node : source.vertexSet()) {
            result.addVertex(node);
         }
      }
      addEdges(result, source, null, false, edgeKeys(result));
      return result;
   }

   public static DirectedPseudograph<EntityNode, EventEdge> union(
      DirectedPseudograph<EntityNode, EventEdge> left, DirectedPseudograph<EntityNode, EventEdge> right
   ) {
      DirectedPseudograph<EntityNode, EventEdge> result = copy(left);
      if (right != null) {
         for (EntityNode node : right.vertexSet()) {
            if (!result.containsVertex(node)) {
               result.addVertex(node);
            }
         }
      }
      addEdges(result, right, null, false, edgeKeys(result));
      return result;
   }

   public static DirectedPseudograph<EntityNode, EventEdge> intersection(
      DirectedPseudograph<EntityNode, EventEdge> left, DirectedPseudograph<EntityNode, EventEdge> right
   ) {
      Set<String> rightKeys = edgeKeys(right);
      return select(left, rightKeys, true);
   }

   public static DirectedPseudograph<EntityNode, EventEdge> difference(
      DirectedPseudograph<EntityNode, EventEdge> left, DirectedPseudograph<EntityNode, EventEdge> excluded
   ) {
      Set<String> excludedKeys = edgeKeys(excluded);
      return select(left, excludedKeys, false);
   }

   public static DirectedPseudograph<EntityNode, EventEdge> attackComponents(
      DirectedPseudograph<EntityNode, EventEdge> graph, Set<Long> entryNodeIds, Set<Long> poiNodeIds
   ) {
      DirectedPseudograph<EntityNode, EventEdge> result = new DirectedPseudograph(EventEdge.class);
      if (graph == null || entryNodeIds == null || entryNodeIds.isEmpty() || poiNodeIds == null || poiNodeIds.isEmpty()) {
         return result;
      }

      Map<Long, EntityNode> nodes = new LinkedHashMap<>();
      Map<Long, Set<Long>> neighbors = new HashMap<>();
      for (EntityNode node : graph.vertexSet()) {
         nodes.put(node.getId(), node);
         neighbors.put(node.getId(), new LinkedHashSet<Long>());
      }
      for (EventEdge edge : graph.edgeSet()) {
         long sourceId = edge.getSource().getId();
         long sinkId = edge.getSink().getId();
         neighbors.get(sourceId).add(sinkId);
         neighbors.get(sinkId).add(sourceId);
      }

      Set<Long> keptNodeIds = new LinkedHashSet<>();
      Set<Long> visited = new HashSet<>();
      for (Long root : nodes.keySet()) {
         if (!visited.add(root)) {
            continue;
         }
         Set<Long> component = new LinkedHashSet<>();
         Queue<Long> queue = new ArrayDeque<>();
         queue.add(root);
         component.add(root);
         boolean hasEntry = entryNodeIds.contains(root);
         boolean hasPoi = poiNodeIds.contains(root);
         while (!queue.isEmpty()) {
            Long current = queue.remove();
            for (Long neighbor : neighbors.get(current)) {
               if (visited.add(neighbor)) {
                  queue.add(neighbor);
                  component.add(neighbor);
                  hasEntry = hasEntry || entryNodeIds.contains(neighbor);
                  hasPoi = hasPoi || poiNodeIds.contains(neighbor);
               }
            }
         }
         if (hasEntry && hasPoi) {
            keptNodeIds.addAll(component);
         }
      }

      Set<String> retainedEdgeKeys = edgeKeys(result);
      for (EventEdge edge : graph.edgeSet()) {
         if (keptNodeIds.contains(edge.getSource().getId()) && keptNodeIds.contains(edge.getSink().getId())) {
            addCopiedEdge(result, edge, retainedEdgeKeys, CanonicalEdgeIdentity.key(edge));
         }
      }
      return result;
   }

   public static Set<String> edgeKeys(DirectedPseudograph<EntityNode, EventEdge> graph) {
      Set<String> keys = new LinkedHashSet<>();
      if (graph != null) {
         for (EventEdge edge : graph.edgeSet()) {
            keys.add(CanonicalEdgeIdentity.key(edge));
         }
      }
      return keys;
   }

   private static DirectedPseudograph<EntityNode, EventEdge> select(
      DirectedPseudograph<EntityNode, EventEdge> source, Set<String> keys, boolean includeMatching
   ) {
      DirectedPseudograph<EntityNode, EventEdge> result = new DirectedPseudograph(EventEdge.class);
      addEdges(result, source, keys, includeMatching, edgeKeys(result));
      return result;
   }

   private static void addEdges(
      DirectedPseudograph<EntityNode, EventEdge> target,
      DirectedPseudograph<EntityNode, EventEdge> source,
      Set<String> keys,
      boolean includeMatching,
      Set<String> targetKeys
   ) {
      if (source == null) {
         return;
      }
      for (EventEdge edge : source.edgeSet()) {
         String edgeKey = CanonicalEdgeIdentity.key(edge);
         boolean matches = keys != null && keys.contains(edgeKey);
         if (keys != null && matches != includeMatching) {
            continue;
         }
         addCopiedEdge(target, edge, targetKeys, edgeKey);
      }
   }

   private static void addCopiedEdge(DirectedPseudograph<EntityNode, EventEdge> graph, EventEdge edge, Set<String> graphKeys, String edgeKey) {
      if (edge == null || graph == null) {
         return;
      }
      if (!graphKeys.add(edgeKey)) {
         return;
      }
      EntityNode source = edge.getSource();
      EntityNode sink = edge.getSink();
      if (!graph.containsVertex(source)) {
         graph.addVertex(source);
      }
      if (!graph.containsVertex(sink)) {
         graph.addVertex(sink);
      }
      graph.addEdge(source, sink, new EventEdge(edge));
   }
}
