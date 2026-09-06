package util;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

public class CausalityPreserve {
   DirectedPseudograph<EntityNode, EventEdge> input;
   public DirectedPseudograph<EntityNode, EventEdge> afterMerge;

   public CausalityPreserve(DirectedPseudograph<EntityNode, EventEdge> input) {
      this.input = (DirectedPseudograph<EntityNode, EventEdge>)input.clone();
   }

   private Map<String, Map<EntityNode, Map<EntityNode, Stack<EventEdge>>>> initializePairStack(Set<EventEdge> edges) {
      Map<String, Map<EntityNode, Map<EntityNode, Stack<EventEdge>>>> map = new HashMap<>();

      for (EventEdge e : edges) {
         String event = e.getEvent();
         map.putIfAbsent(event, new HashMap<>());
         Map<EntityNode, Map<EntityNode, Stack<EventEdge>>> eventMap = map.get(event);
         EntityNode source = e.getSource();
         EntityNode target = e.getSink();
         eventMap.putIfAbsent(source, new HashMap<>());
         eventMap.get(source).putIfAbsent(target, new Stack<>());
      }

      return map;
   }

   private DirectedPseudograph<EntityNode, EventEdge> mergeEdgeOnSeconds(double range) {
      DirectedPseudograph<EntityNode, EventEdge> merged = new DirectedPseudograph(EventEdge.class);
      Comparator<EventEdge> cmp = new Comparator<EventEdge>() {
         public int compare(EventEdge a, EventEdge b) {
            return new BigDecimal(a.getStartns() / 1000000000L).compareTo(new BigDecimal(b.getStartns() / 1000000000L)) == 0
               ? new BigDecimal(a.getEndns() / 1000000000L).compareTo(new BigDecimal(b.getEndns() / 1000000000L))
               : new BigDecimal(a.getStartns() / 1000000000L).compareTo(new BigDecimal(b.getStartns() / 1000000000L));
         }
      };
      BigDecimal timeDiff = new BigDecimal(range);
      Set<EventEdge> edgeSet = this.input.edgeSet();
      List<EventEdge> edgeList = new LinkedList<>(edgeSet);
      Collections.sort(edgeList, cmp);
      Iterator<EventEdge> iter = edgeList.iterator();
      Map<String, Map<EntityNode, Map<EntityNode, Stack<EventEdge>>>> pairStacks = this.initializePairStack(edgeSet);

      while (iter.hasNext()) {
         EventEdge cur = iter.next();
         EntityNode source = cur.getSource();
         EntityNode target = cur.getSink();
         Stack<EventEdge> stack = pairStacks.get(cur.getEvent()).get(source).get(target);
         if (stack.isEmpty()) {
            stack.push(cur);
         } else {
            EventEdge edgePrevious = stack.pop();
            BigDecimal diff = new BigDecimal(cur.getStartns() / 1000000000L).subtract(new BigDecimal(edgePrevious.getEndns() / 1000000000L));
            if (diff.compareTo(timeDiff) <= 0 && edgePrevious.getEvent().equals(cur.getEvent())) {
               edgePrevious = edgePrevious.merge(cur);
               stack.push(edgePrevious);
            } else {
               stack.push(edgePrevious);
               stack.push(cur);
            }
         }
      }

      for (String event : pairStacks.keySet()) {
         for (EntityNode source : pairStacks.get(event).keySet()) {
            for (EntityNode sink : pairStacks.get(event).get(source).keySet()) {
               for (EventEdge e : pairStacks.get(event).get(source).get(sink)) {
                  merged.addEdge(source, sink, e);
               }
            }
         }
      }

      this.afterMerge = merged;
      return this.afterMerge;
   }

   public DirectedPseudograph<EntityNode, EventEdge> mergeEdgeFallInTheRange2(double range) {
      DirectedPseudograph<EntityNode, EventEdge> merged = new DirectedPseudograph(EventEdge.class);

      for (EntityNode n : this.input.vertexSet()) {
         merged.addVertex(n);
      }

      Comparator<EventEdge> cmp = new Comparator<EventEdge>() {
         public int compare(EventEdge a, EventEdge b) {
            return a.getStartTime().compareTo(b.getStartTime()) == 0 ? a.getEndTime().compareTo(b.getEndTime()) : a.getStartTime().compareTo(b.getStartTime());
         }
      };
      BigDecimal timeDiff = new BigDecimal(range);
      Set<EventEdge> edgeSet = this.input.edgeSet();
      List<EventEdge> edgeList = new LinkedList<>(edgeSet);
      Collections.sort(edgeList, cmp);
      Iterator<EventEdge> iter = edgeList.iterator();
      Map<String, Map<EntityNode, Map<EntityNode, Stack<EventEdge>>>> pairStacks = this.initializePairStack(edgeSet);

      while (iter.hasNext()) {
         EventEdge cur = iter.next();
         EntityNode source = cur.getSource();
         EntityNode target = cur.getSink();
         Stack<EventEdge> stack = pairStacks.get(cur.getEvent()).get(source).get(target);
         if (stack.isEmpty()) {
            stack.push(cur);
         } else {
            EventEdge edgePrevious = stack.pop();
            BigDecimal diff = cur.getStartTime().subtract(edgePrevious.endTime);
            if (diff.compareTo(timeDiff) <= 0) {
               edgePrevious = edgePrevious.merge(cur);
               stack.push(edgePrevious);
            } else {
               stack.push(edgePrevious);
               stack.push(cur);
            }
         }
      }

      for (String event : pairStacks.keySet()) {
         for (EntityNode source : pairStacks.get(event).keySet()) {
            for (EntityNode sink : pairStacks.get(event).get(source).keySet()) {
               for (EventEdge e : pairStacks.get(event).get(source).get(sink)) {
                  merged.addEdge(source, sink, e);
               }
            }
         }
      }

      this.afterMerge = merged;
      return this.afterMerge;
   }
}
