package util;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

/**
 * ForwardAnalysis - 内存因果子图的前向影响分析
 * 
 * 移植自 DepImpact (USENIX Security 2020) 原生 ForwardAnalysis 算法。
 * 直接在经过后向切片与因果压缩后的子图 (b_cpr) 上运行，沿着因果发生顺序向未来方向扩展，
 * 且所有前向边的发生时间不超过 POI 发生时间 (POITime)。
 */
public class ForwardAnalysis {
   private final DirectedPseudograph<EntityNode, EventEdge> input;

   public ForwardAnalysis(DirectedPseudograph<EntityNode, EventEdge> graph) {
      this.input = graph;
   }

   public DirectedPseudograph<EntityNode, EventEdge> forwardLimitedByTime(EntityNode start, BigDecimal poiTime) {
      DirectedPseudograph<EntityNode, EventEdge> res = new DirectedPseudograph<>(EventEdge.class);
      if (start == null || !this.input.containsVertex(start)) {
         return res;
      }

      Queue<EntityNode> queue = new LinkedList<>();
      queue.offer(start);
      Queue<EntityNode> nextQueue = new LinkedList<>();

      while (!queue.isEmpty()) {
         while (!queue.isEmpty()) {
            EntityNode cur = queue.poll();
            if (res.vertexSet().isEmpty()) {
               res.addVertex(cur);
               Set<EventEdge> outgoing = this.input.outgoingEdgesOf(cur);
               for (EventEdge out : outgoing) {
                  if (poiTime == null || out.getStartTime() == null || out.getStartTime().compareTo(poiTime) <= 0) {
                     EntityNode target = out.getSink();
                     if (res.addVertex(target)) {
                        nextQueue.offer(target);
                     }
                     res.addEdge(cur, target, out);
                  }
               }
            } else {
               res.addVertex(cur);
               BigDecimal earliestStart = getEarliestOPTime(cur, res);
               Set<EventEdge> outgoing = this.input.outgoingEdgesOf(cur);
               for (EventEdge out : outgoing) {
                  if (poiTime == null || out.getStartTime() == null || out.getStartTime().compareTo(poiTime) <= 0) {
                     if (earliestStart != null && out.getStartTime() != null && out.getStartTime().compareTo(earliestStart) < 0) {
                        continue;
                     }
                     EntityNode target = out.getSink();
                     if (res.addVertex(target)) {
                        nextQueue.offer(target);
                     }
                     res.addEdge(cur, target, out);
                  }
               }
            }
         }
         queue = nextQueue;
         nextQueue = new LinkedList<>();
      }
      return res;
   }

   private BigDecimal getEarliestOPTime(EntityNode node, DirectedPseudograph<EntityNode, EventEdge> res) {
      Set<EventEdge> incoming = res.incomingEdgesOf(node);
      if (incoming == null || incoming.isEmpty()) {
         return null;
      }
      BigDecimal min = null;
      for (EventEdge edge : incoming) {
         BigDecimal st = edge.getStartTime();
         if (st != null) {
            if (min == null || st.compareTo(min) < 0) {
               min = st;
            }
         }
      }
      return min;
   }
}
