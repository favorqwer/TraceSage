package traversal.neo4jserver;

import com.fathzer.soft.javaluator.AbstractEvaluator;
import gql.Expression;
import gql.PropertyExpression;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import model.Edge;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;
import util.ExpressionUtils;
import util.TextualOperatorsEvaluator;

/**
 * Expands causally valid outgoing edges BFS-style: an edge current -> child
 * is followed when its endtime is later than the current node's causal
 * threshold (the earliest starttime among the edges that discovered the
 * node, min-kept), and the child inherits the edge's starttime as its own
 * threshold.
 *
 * No per-relationship syscall filter is applied: sysdig-parser only emits
 * edges for provenance-relevant syscalls, so every edge in the store is
 * traversable (see Neo4jBackwardExpander for the rationale).
 */
public class Neo4jForwardExpander {
   private Queue<String> expQueue = new LinkedList<>();
   private List<String> keyLst = new ArrayList<>();
   private Edge edge;
   private Expression exprInWhere;
   private List<PropertyExpression> propertyExpressionLst;
   private DirectedPseudograph<EntityNode, EventEdge> jg;
   private Neo4jSession sessions;
   private Neo4jNodeRegistry registry;
   private static AbstractEvaluator<Boolean> evaluator = new TextualOperatorsEvaluator();
   private HashMap<EntityNode, Long> timeMap = new HashMap<>();
   EntityNode startNode;
   long edgeTime;

   public Neo4jForwardExpander(
      EntityNode startNode, long edgeTime, Edge edge, Expression exprInWhere,
      DirectedPseudograph<EntityNode, EventEdge> jg, Neo4jSession sessions, Neo4jNodeRegistry registry
   ) {
      this.startNode = startNode;
      this.edgeTime = edgeTime;
      this.edge = edge;
      this.exprInWhere = exprInWhere;
      this.jg = jg;
      this.sessions = sessions;
      this.registry = registry;
      this.propertyExpressionLst = exprInWhere.getPropertyExpressionLst();
      this.expQueue = ExpressionUtils.extractExpFromWhere(exprInWhere.toString());
      this.keyLst = ExpressionUtils.extractKeyFromWhere(exprInWhere.toString());
   }

   public void expand() {
      String trueFalseWhere = "";
      Queue<EntityNode> queue = new LinkedList<>();
      queue.offer(this.startNode);
      this.jg.addVertex(this.startNode);
      this.timeMap.putIfAbsent(this.startNode, this.edgeTime);
      if (this.exprInWhere.getTraversalExpression() != null) {
         String collectExp = ExpressionUtils.extractCollectExp(this.expQueue);
         collectExp = collectExp.replaceAll("max\\s*\\(", "max(");
         collectExp = collectExp.replaceAll("min\\s*\\(", "min(");
         String property = "";
         String compareProp = collectExp.substring(collectExp.lastIndexOf(46));
         if (compareProp.contains("starttime")) {
            property = "starttime";
         }

         if (compareProp.contains("endtime")) {
            property = "endtime";
         }

         while (!queue.isEmpty()) {
            EntityNode curNode = queue.poll();
            long curThreshold = this.timeMap.get(curNode);
            Neo4jRowCursor rs = this.connectedEdges(curNode);
            try {
               while (rs.next()) {
                  trueFalseWhere = "";
                  int index = 0;

                  for (String exp : this.expQueue) {
                     index++;
                     if (exp.contains("collect")) {
                        exp = exp.replaceAll("(max|min)\\s*\\(.*\\.(endtime|starttime)\\s*((\\)\\s*){2})", String.valueOf(curThreshold));
                     }

                     String expNoP = exp.replace("(", "").replace(")", "");
                     if (index <= this.expQueue.size() - 1) {
                        trueFalseWhere = trueFalseWhere
                           + exp.replace(expNoP, ExpressionUtils.doIt(this.edge, rs, ExpressionUtils.parseExpression(expNoP)))
                           + " "
                           + this.keyLst.get(index - 1)
                           + " ";
                     } else {
                        trueFalseWhere = trueFalseWhere
                           + exp.replace(expNoP, ExpressionUtils.doIt(this.edge, rs, ExpressionUtils.parseExpression(expNoP)));
                     }
                  }

                  if ((Boolean)evaluator.evaluate(trueFalseWhere)) {
                     EntityNode eNode = this.registry.nodeByKey(
                        rs.getString("childlabel"), rs.getString("childkey"), this.sessions
                     );
                     if (eNode == null) {
                        System.err.println(
                           "Skipping forward edge because child node was not found. childkey="
                              + rs.getString("childkey")
                              + ", eventid="
                              + rs.getLong("eventid")
                        );
                        continue;
                     }

                     if (!this.jg.containsVertex(eNode)) {
                        this.jg.addVertex(eNode);
                        queue.offer(eNode);
                     }

                     long thresholdForSink = rs.getLong(property);
                     if (collectExp.contains("max(")) {
                        this.timeMap.putIfAbsent(eNode, 0L);
                        if (this.timeMap.get(eNode).compareTo(thresholdForSink) < 0) {
                           this.timeMap.put(eNode, thresholdForSink);
                        }
                     } else if (collectExp.contains("min(")) {
                        this.timeMap.putIfAbsent(eNode, Long.MAX_VALUE);
                        if (this.timeMap.get(eNode).compareTo(thresholdForSink) > 0) {
                           this.timeMap.put(eNode, thresholdForSink);
                        }
                     }

                     EventEdge e = ExpressionUtils.createEventEdge(curNode, eNode, rs);
                     if (!this.jg.containsEdge(e)) {
                        this.jg.addEdge(curNode, eNode, e);
                     }
                  }
               }
            } catch (Exception ex) {
               ex.printStackTrace();
            } finally {
               rs.close();
            }
         }
      } else {
         while (!queue.isEmpty()) {
            EntityNode curNode = queue.poll();
            Neo4jRowCursor rs = this.connectedEdges(curNode);
            try {
               while (rs.next()) {
                  trueFalseWhere = "";
                  int index = 0;

                  for (String exp : this.expQueue) {
                     index++;
                     String expNoParenthesis = exp.replace("(", "").replace(")", "");
                     if (index <= this.expQueue.size() - 1) {
                        trueFalseWhere = trueFalseWhere
                           + exp.replace(expNoParenthesis, ExpressionUtils.doIt(this.edge, rs, ExpressionUtils.parseExpression(expNoParenthesis)))
                           + " "
                           + this.keyLst.get(index - 1)
                           + " ";
                     } else {
                        trueFalseWhere = trueFalseWhere
                           + exp.replace(expNoParenthesis, ExpressionUtils.doIt(this.edge, rs, ExpressionUtils.parseExpression(expNoParenthesis)));
                     }
                  }

                  if ((Boolean)evaluator.evaluate(trueFalseWhere)) {
                     EntityNode eNode = this.registry.nodeByKey(
                        rs.getString("childlabel"), rs.getString("childkey"), this.sessions
                     );
                     if (eNode == null) {
                        System.err.println(
                           "Skipping forward edge because child node was not found. childkey="
                              + rs.getString("childkey")
                              + ", eventid="
                              + rs.getLong("eventid")
                        );
                        continue;
                     }

                     if (!this.jg.containsVertex(eNode)) {
                        this.jg.addVertex(eNode);
                        queue.offer(eNode);
                     }

                     EventEdge e = ExpressionUtils.createEventEdge(curNode, eNode, rs);
                     if (!this.jg.containsEdge(e)) {
                        this.jg.addEdge(curNode, eNode, e);
                     }
                  }
               }
            } catch (Exception ex) {
               ex.printStackTrace();
            } finally {
               rs.close();
            }
         }
      }
   }

   /** Outgoing (current -> child) event rows for one node, ordered by eventid. */
   private Neo4jRowCursor connectedEdges(EntityNode curNode) {
      String label = curNode.getF() != null
         ? Neo4jNodeRegistry.LABEL_FILE
         : curNode.getP() != null ? Neo4jNodeRegistry.LABEL_PROCESS : Neo4jNodeRegistry.LABEL_NETWORK;
      String keyProp = Neo4jNodeRegistry.keyProperty(label);
      String key = this.registry.keyOf(curNode.getId());
      String edgeColumns = "r.event_id AS eventid, r.starttime AS starttime, r.endtime AS endtime, "
         + "r.syscall AS optype, coalesce(r.bytes, 0) AS amount, \"\" AS hostname";

      StringBuilder cypher = new StringBuilder();
      if (Neo4jNodeRegistry.LABEL_PROCESS.equals(label)) {
         cypher.append("MATCH (cur:Process {").append(keyProp).append(": $key})-[r:p2p]->(child:Process) ")
            .append("RETURN ").append(edgeColumns).append(", child.process_id AS childkey, 'Process' AS childlabel ")
            .append("UNION ALL ")
            .append("MATCH (cur:Process {").append(keyProp).append(": $key})-[r:p2f]->(child:File) ")
            .append("RETURN ").append(edgeColumns).append(", child.file_id AS childkey, 'File' AS childlabel ")
            .append("UNION ALL ")
            .append("MATCH (cur:Process {").append(keyProp).append(": $key})-[r:p2n]->(child:Network) ")
            .append("RETURN ").append(edgeColumns).append(", child.network_id AS childkey, 'Network' AS childlabel ");
      } else if (Neo4jNodeRegistry.LABEL_FILE.equals(label)) {
         cypher.append("MATCH (cur:File {").append(keyProp).append(": $key})-[r:f2p]->(child:Process) ")
            .append("RETURN ").append(edgeColumns).append(", child.process_id AS childkey, 'Process' AS childlabel ");
      } else {
         cypher.append("MATCH (cur:Network {").append(keyProp).append(": $key})-[r:n2p]->(child:Process) ")
            .append("RETURN ").append(edgeColumns).append(", child.process_id AS childkey, 'Process' AS childlabel ");
      }
      cypher.append("ORDER BY eventid");

      Map<String, Object> params = new HashMap<>();
      params.put("key", key);

      List<Map<String, Object>> rows = new ArrayList<>();
      for (org.neo4j.driver.Record record : this.sessions.run(cypher.toString(), params)) {
         rows.add(record.asMap());
      }
      return new Neo4jRowCursor(
         rows,
         List.of("eventid", "starttime", "endtime", "optype", "amount", "hostname", "childkey", "childlabel")
      );
   }
}
