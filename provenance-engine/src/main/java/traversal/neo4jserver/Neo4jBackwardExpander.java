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
 * Expands causally valid incoming edges BFS-style: an edge parent -> current
 * is followed when its starttime is earlier than the current node's causal
 * threshold, and the parent inherits the edge's endtime as its own (max-kept)
 * threshold.
 *
 * No per-relationship syscall filter is applied: sysdig-parser only emits
 * edges for provenance-relevant syscalls (unmatched events never become
 * edges), so every edge in the store is traversable. Filtering here against a
 * second copy of the parser's vocabulary silently dropped real edges whenever
 * the two copies drifted (f2p execve/open, p2f open/unlink/... were lost).
 */
public class Neo4jBackwardExpander {
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

   public Neo4jBackwardExpander(
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
                     EntityNode sNode = this.registry.nodeByKey(
                        rs.getString("parentlabel"), rs.getString("parentkey"), this.sessions
                     );
                     if (sNode == null) {
                        System.err.println(
                           "Skipping backward edge because parent node was not found. parentkey="
                              + rs.getString("parentkey")
                              + ", eventid="
                              + rs.getLong("eventid")
                        );
                        continue;
                     }

                     if (!this.jg.containsVertex(sNode)) {
                        this.jg.addVertex(sNode);
                        queue.offer(sNode);
                     }

                     long thresholdForSource = rs.getLong(property);
                     if (collectExp.contains("max(")) {
                        this.timeMap.putIfAbsent(sNode, 0L);
                        if (this.timeMap.get(sNode).compareTo(thresholdForSource) < 0) {
                           this.timeMap.put(sNode, thresholdForSource);
                        }
                     } else if (collectExp.contains("min(")) {
                        this.timeMap.putIfAbsent(sNode, Long.MAX_VALUE);
                        if (this.timeMap.get(sNode).compareTo(thresholdForSource) > 0) {
                           this.timeMap.put(sNode, thresholdForSource);
                        }
                     }

                     EventEdge e = ExpressionUtils.createEventEdge(sNode, curNode, rs);
                     if (!this.jg.containsEdge(e)) {
                        this.jg.addEdge(sNode, curNode, e);
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
                     EntityNode sNode = this.registry.nodeByKey(
                        rs.getString("parentlabel"), rs.getString("parentkey"), this.sessions
                     );
                     if (sNode == null) {
                        System.err.println(
                           "Skipping backward edge because parent node was not found. parentkey="
                              + rs.getString("parentkey")
                              + ", eventid="
                              + rs.getLong("eventid")
                        );
                        continue;
                     }

                     if (!this.jg.containsVertex(sNode)) {
                        this.jg.addVertex(sNode);
                        queue.offer(sNode);
                     }

                     EventEdge e = ExpressionUtils.createEventEdge(sNode, curNode, rs);
                     if (!this.jg.containsEdge(e)) {
                        this.jg.addEdge(sNode, curNode, e);
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

   /** Incoming (parent -> current) event rows for one node, ordered by eventid. */
   private Neo4jRowCursor connectedEdges(EntityNode curNode) {
      String label = curNode.getF() != null
         ? Neo4jNodeRegistry.LABEL_FILE
         : curNode.getP() != null ? Neo4jNodeRegistry.LABEL_PROCESS : Neo4jNodeRegistry.LABEL_NETWORK;
      String key = this.registry.keyOf(curNode.getId());
      Map<String, Object> params = new HashMap<>();
      String curMatch = Neo4jNodeRegistry.matchCurClause("cur", label, key, params);
      String edgeColumns = "r.event_id AS eventid, coalesce(r.start_ns, r.starttime) AS starttime, "
         + "coalesce(r.end_ns, r.endtime) AS endtime, coalesce(r.syscall, r.action) AS optype, "
         + "CASE WHEN coalesce(r.result, r.bytes, 0) > 0 THEN coalesce(r.result, r.bytes, 0) ELSE 0 END AS amount, \"\" AS hostname";

      StringBuilder cypher = new StringBuilder();
      if (Neo4jNodeRegistry.LABEL_PROCESS.equals(label)) {
         cypher.append("MATCH (parent:Process)-[r:ProcessToProcess|p2p]->").append(curMatch).append(" ")
            .append("RETURN ").append(edgeColumns).append(", ")
            .append(Neo4jNodeRegistry.keyProjection("parent", Neo4jNodeRegistry.LABEL_PROCESS))
            .append(" AS parentkey, 'Process' AS parentlabel ")
            .append("UNION ALL ")
            .append("MATCH (parent:Network)-[r:NetworkToProcess|n2p]->").append(curMatch).append(" ")
            .append("RETURN ").append(edgeColumns).append(", ")
            .append(Neo4jNodeRegistry.keyProjection("parent", Neo4jNodeRegistry.LABEL_NETWORK))
            .append(" AS parentkey, 'Network' AS parentlabel ")
            .append("UNION ALL ")
            .append("MATCH (parent:File)-[r:FileToProcess|f2p]->").append(curMatch).append(" ")
            .append("RETURN ").append(edgeColumns).append(", ")
            .append(Neo4jNodeRegistry.keyProjection("parent", Neo4jNodeRegistry.LABEL_FILE))
            .append(" AS parentkey, 'File' AS parentlabel ");
      } else if (Neo4jNodeRegistry.LABEL_FILE.equals(label)) {
         cypher.append("MATCH (parent:Process)-[r:ProcessToFile|p2f]->").append(curMatch).append(" ")
            .append("RETURN ").append(edgeColumns).append(", ")
            .append(Neo4jNodeRegistry.keyProjection("parent", Neo4jNodeRegistry.LABEL_PROCESS))
            .append(" AS parentkey, 'Process' AS parentlabel ");
      } else {
         cypher.append("MATCH (parent:Process)-[r:ProcessToNetwork|p2n]->").append(curMatch).append(" ")
            .append("RETURN ").append(edgeColumns).append(", ")
            .append(Neo4jNodeRegistry.keyProjection("parent", Neo4jNodeRegistry.LABEL_PROCESS))
            .append(" AS parentkey, 'Process' AS parentlabel ");
      }
      cypher.append("ORDER BY eventid");

      List<Map<String, Object>> rows = new ArrayList<>();
      for (org.neo4j.driver.Record record : this.sessions.run(cypher.toString(), params)) {
         rows.add(record.asMap());
      }
      return new Neo4jRowCursor(
         rows,
         List.of("eventid", "starttime", "endtime", "optype", "amount", "hostname", "parentkey", "parentlabel")
      );
   }
}
