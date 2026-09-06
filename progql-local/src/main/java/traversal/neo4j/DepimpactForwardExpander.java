package traversal.neo4j;

import com.fathzer.soft.javaluator.AbstractEvaluator;
import com.google.common.collect.Lists;
import gql.Expression;
import gql.PropertyExpression;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import main.Main;
import model.Edge;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;
import org.neo4j.graphdb.Direction;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Path;
import org.neo4j.graphdb.PathExpander;
import org.neo4j.graphdb.Relationship;
import org.neo4j.graphdb.traversal.BranchState;
import util.ExpressionUtils;
import util.TextualOperatorsEvaluator;

public class DepimpactForwardExpander implements PathExpander {
   private Queue<String> expQueue = new LinkedList<>();
   private List<String> keyLst = new ArrayList<>();
   private Edge edge;
   private Expression exprInWhere;
   private List<PropertyExpression> propertyExpressionLst;
   private DirectedPseudograph<EntityNode, EventEdge> jg;
   private static AbstractEvaluator<Boolean> evaluator = new TextualOperatorsEvaluator();
   private HashMap<Node, Long> timeMap = new HashMap<>();
   long edgeTime;

   public DepimpactForwardExpander(long edgeTime, Edge edge, Expression exprInWhere, DirectedPseudograph<EntityNode, EventEdge> jg) {
      this.edgeTime = edgeTime;
      this.edge = edge;
      this.exprInWhere = exprInWhere;
      this.jg = jg;
      this.propertyExpressionLst = exprInWhere.getPropertyExpressionLst();
      this.expQueue = ExpressionUtils.extractExpFromWhere(exprInWhere.toString());
      this.keyLst = ExpressionUtils.extractKeyFromWhere(exprInWhere.toString());
   }

   public Iterable expand(Path path, BranchState state) {
      String trueFalseWhere = "";
      int depth = path.length();
      Node currentNode = path.endNode();
      EntityNode sNode = Main.getEntityNode(currentNode);
      if (depth == 0) {
         this.jg.addVertex(sNode);
         this.timeMap.putIfAbsent(currentNode, this.edgeTime);
      }

      if (this.exprInWhere.getTraversalExpression() == null) {
         List<Relationship> rsLst = new ArrayList<>();
         List<Relationship> outgoingRsLst = Lists.newArrayList(currentNode.getRelationships(Direction.OUTGOING));
         Collections.sort(outgoingRsLst, (r1, r2) -> Integer.parseInt(r1.getProperty("id").toString()) - Integer.parseInt(r2.getProperty("id").toString()));

         for (Relationship r : ExpressionUtils.getIterableFromIterator(outgoingRsLst.iterator())) {
            if (this.isRelationshipIncluded(currentNode, r, "outgoing")) {
               trueFalseWhere = "";
               int index = 0;

               for (String exp : this.expQueue) {
                  index++;
                  String expNoParenthesis = exp.replace("(", "").replace(")", "");
                  if (index <= this.expQueue.size() - 1) {
                     trueFalseWhere = trueFalseWhere
                        + exp.replace(expNoParenthesis, ExpressionUtils.doIt(this.edge, r, ExpressionUtils.parseExpression(expNoParenthesis)))
                        + " "
                        + this.keyLst.get(index - 1)
                        + " ";
                  } else {
                     trueFalseWhere = trueFalseWhere
                        + exp.replace(expNoParenthesis, ExpressionUtils.doIt(this.edge, r, ExpressionUtils.parseExpression(expNoParenthesis)));
                  }
               }

               if ((Boolean)evaluator.evaluate(trueFalseWhere)) {
                  rsLst.add(r);
                  EntityNode eNode = Main.getEntityNode(r.getEndNode());
                  if (!this.jg.containsVertex(eNode)) {
                     this.jg.addVertex(eNode);
                  }

                  EventEdge e = ExpressionUtils.createEventEdge(sNode, eNode, r);
                  if (!this.jg.containsEdge(e)) {
                     this.jg.addEdge(sNode, eNode, e);
                  }
               }
            }
         }

         Iterator<Relationship> rsIterator = rsLst.iterator();
         return ExpressionUtils.getIterableFromIterator(rsIterator);
      } else {
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

         long curThreshold = this.timeMap.get(currentNode);
         if (!collectExp.contains("in(")) {
            return null;
         } else {
            List<Relationship> rsLst = new ArrayList<>();
            List<Relationship> outgoingRsLst = Lists.newArrayList(currentNode.getRelationships(Direction.OUTGOING));
            Collections.sort(outgoingRsLst, (r1, r2) -> Integer.parseInt(r1.getProperty("id").toString()) - Integer.parseInt(r2.getProperty("id").toString()));

            for (Relationship rx : ExpressionUtils.getIterableFromIterator(outgoingRsLst.iterator())) {
               if (this.isRelationshipIncluded(currentNode, rx, "outgoing")) {
                  trueFalseWhere = "";
                  int index = 0;

                  for (String expx : this.expQueue) {
                     index++;
                     if (expx.contains("collect")) {
                        expx = expx.replaceAll("(max|min)\\s*\\(.*\\.(endtime|starttime)\\s*((\\)\\s*){2})", String.valueOf(curThreshold));
                     }

                     String expNoP = expx.replace("(", "").replace(")", "");
                     if (index <= this.expQueue.size() - 1) {
                        trueFalseWhere = trueFalseWhere
                           + expx.replace(expNoP, ExpressionUtils.doIt(this.edge, rx, ExpressionUtils.parseExpression(expNoP)))
                           + " "
                           + this.keyLst.get(index - 1)
                           + " ";
                     } else {
                        trueFalseWhere = trueFalseWhere + expx.replace(expNoP, ExpressionUtils.doIt(this.edge, rx, ExpressionUtils.parseExpression(expNoP)));
                     }
                  }

                  if ((Boolean)evaluator.evaluate(trueFalseWhere)) {
                     EntityNode eNodex = Main.getEntityNode(rx.getEndNode());
                     if (!this.jg.containsVertex(eNodex)) {
                        this.jg.addVertex(eNodex);
                     }

                     long thresholdForSink = (Long)rx.getProperty(property);
                     if (collectExp.contains("max(")) {
                        this.timeMap.putIfAbsent(rx.getEndNode(), 0L);
                        if (this.timeMap.get(rx.getEndNode()).compareTo(thresholdForSink) < 0) {
                           this.timeMap.put(rx.getEndNode(), thresholdForSink);
                        }
                     } else if (collectExp.contains("min(")) {
                        this.timeMap.putIfAbsent(rx.getEndNode(), Long.MAX_VALUE);
                        if (this.timeMap.get(rx.getEndNode()).compareTo(thresholdForSink) > 0) {
                           this.timeMap.put(rx.getEndNode(), thresholdForSink);
                        }
                     }

                     rsLst.add(rx);
                     EventEdge e = ExpressionUtils.createEventEdge(sNode, eNodex, rx);
                     if (!this.jg.containsEdge(e)) {
                        this.jg.addEdge(sNode, eNodex, e);
                     }
                  }
               }
            }

            Iterator<Relationship> rsIterator = rsLst.iterator();
            return ExpressionUtils.getIterableFromIterator(rsIterator);
         }
      }
   }

   public PathExpander reverse() {
      return null;
   }

   private boolean isRelationshipIncluded(Node currentNode, Relationship r, String direction) {
      if (direction.equals("incoming")) {
         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.File)
            && "write,writev,rename,modify_file_attributes,create_object".contains(r.getProperty("optype").toString().toLowerCase())
            && r.isType(Neo4jTraversal.MyRelationshipType.FileEvent)) {
            return true;
         }

         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.Process)) {
            if ("execve,execute,clone".contains(r.getProperty("optype").toString().toLowerCase()) && r.isType(Neo4jTraversal.MyRelationshipType.ProcessEvent)) {
               return true;
            }

            if ("read,readv,execute,rename".contains(r.getProperty("optype").toString().toLowerCase()) && r.isType(Neo4jTraversal.MyRelationshipType.FileEvent)
               )
             {
               return true;
            }

            if ("recvmsg,recvfrom,read_socket_params,read,readv".contains(r.getProperty("optype").toString().toLowerCase())
               && r.isType(Neo4jTraversal.MyRelationshipType.NetworkEvent)) {
               return true;
            }
         }

         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.Network)
            && "sendto,sendmsg,write,write_socket_params,connect,writev".contains(r.getProperty("optype").toString().toLowerCase())
            && r.isType(Neo4jTraversal.MyRelationshipType.NetworkEvent)) {
            return true;
         }
      }

      if (direction.equals("outgoing")) {
         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.File)
            && "read,readv,execute,rename".contains(r.getProperty("optype").toString().toLowerCase())
            && r.isType(Neo4jTraversal.MyRelationshipType.FileEvent)) {
            return true;
         }

         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.Process)) {
            if ("execve,execute,clone".contains(r.getProperty("optype").toString().toLowerCase()) && r.isType(Neo4jTraversal.MyRelationshipType.ProcessEvent)) {
               return true;
            }

            if ("write,writev,rename,modify_file_attributes,create_object".contains(r.getProperty("optype").toString().toLowerCase())
               && r.isType(Neo4jTraversal.MyRelationshipType.FileEvent)) {
               return true;
            }

            if ("sendto,sendmsg,write,write_socket_params,connect,writev".contains(r.getProperty("optype").toString().toLowerCase())
               && r.isType(Neo4jTraversal.MyRelationshipType.NetworkEvent)) {
               return true;
            }
         }

         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.Network)
            && "recvmsg,recvfrom,read_socket_params,read,readv".contains(r.getProperty("optype").toString().toLowerCase())
            && r.isType(Neo4jTraversal.MyRelationshipType.NetworkEvent)) {
            return true;
         }
      }

      return false;
   }
}
