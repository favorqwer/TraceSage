package util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

public class IterateGraph {
   DirectedPseudograph<EntityNode, EventEdge> inputgraph;
   Map<String, EntityNode> indexOfNode;

   IterateGraph(DirectedPseudograph<EntityNode, EventEdge> graph) {
      this.inputgraph = graph;
      this.indexOfNode = new HashMap<>();

      for (EntityNode n : graph.vertexSet()) {
         this.indexOfNode.put(n.getSignature(), n);
      }
   }

   public static String convertEdgeToString(EventEdge edge) {
      StringBuilder sb = new StringBuilder();
      sb.append(edge.getSource().getId());
      sb.append(" -> ");
      sb.append(edge.getSink().getId());
      sb.append(" # ");
      sb.append(edge.getID());
      return sb.toString();
   }

   public static Map<String, Integer> groupsEdges(List<DirectedPseudograph<EntityNode, EventEdge>> graphs) {
      Map<String, Integer> edgeCount = new HashMap<>();

      for (DirectedPseudograph<EntityNode, EventEdge> graph : graphs) {
         for (EventEdge edge : graph.edgeSet()) {
            String key = convertEdgeToString(edge);
            if (!edgeCount.containsKey(key)) {
               edgeCount.put(key, 0);
            }

            edgeCount.put(key, edgeCount.get(key) + 1);
         }
      }

      return edgeCount;
   }
}
