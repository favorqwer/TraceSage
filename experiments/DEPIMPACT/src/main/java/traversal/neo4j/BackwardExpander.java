package traversal.neo4j;

import com.fathzer.soft.javaluator.AbstractEvaluator;
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

public class BackwardExpander implements PathExpander {
   private Queue<String> expQueue = new LinkedList<>();
   private List<String> keyLst = new ArrayList<>();
   private Edge edge;
   private String srcdstExp;
   private DirectedPseudograph<EntityNode, EventEdge> jg;
   private static AbstractEvaluator<Boolean> evaluator = new TextualOperatorsEvaluator();
   private HashMap<Node, Long> timeMap = new HashMap<>();

   public BackwardExpander(Edge edge, Queue<String> expQueue, List<String> keyLst, String srcdstExp, DirectedPseudograph<EntityNode, EventEdge> jg) {
      this.edge = edge;
      this.expQueue = expQueue;
      this.keyLst = keyLst;
      this.srcdstExp = srcdstExp;
      this.jg = jg;
   }

   private String extractCollectExp(Queue<String> expQueue) {
      String collectExp = "";

      for (String exp : expQueue) {
         if (exp.contains("collect")) {
            collectExp = exp;
            break;
         }
      }

      return collectExp;
   }

   public Iterable expand(Path path, BranchState state) {
      String trueFalseWhere = "";
      Node currentNode = path.endNode();
      EntityNode eNode = Main.getEntityNode(currentNode);
      if (!this.jg.containsVertex(eNode)) {
         this.jg.addVertex(eNode);
      }

      if (this.expQueue.size() == 0) {
         List<Relationship> rsLst = new ArrayList<>();

         for (Relationship r : currentNode.getRelationships(Direction.INCOMING)) {
            if (this.isRelationshipIncluded(currentNode, r, "incoming")) {
               rsLst.add(r);
               EntityNode sNode = Main.getEntityNode(r.getStartNode());
               if (!this.jg.containsVertex(sNode)) {
                  this.jg.addVertex(sNode);
               }

               EventEdge e = ExpressionUtils.createEventEdge(sNode, eNode, r);
               if (!this.jg.containsEdge(e)) {
                  this.jg.addEdge(sNode, eNode, e);
               }
            }
         }

         Iterator<Relationship> rsIterator = rsLst.iterator();
         return ExpressionUtils.getIterableFromIterator(rsIterator);
      } else if (this.extractCollectExp(this.expQueue).isEmpty()) {
         List<Relationship> rsLst = new ArrayList<>();

         for (Relationship rx : currentNode.getRelationships(Direction.INCOMING)) {
            if (this.isRelationshipIncluded(currentNode, rx, "incoming")) {
               trueFalseWhere = "";
               int index = 0;

               for (String exp : this.expQueue) {
                  index++;
                  String expNoParenthesis = exp.replace("(", "").replace(")", "");
                  if (index <= this.expQueue.size() - 1) {
                     trueFalseWhere = trueFalseWhere
                        + exp.replace(expNoParenthesis, ExpressionUtils.doIt(this.edge, rx, ExpressionUtils.parseExpression(expNoParenthesis)))
                        + " "
                        + this.keyLst.get(index - 1)
                        + " ";
                  } else {
                     trueFalseWhere = trueFalseWhere
                        + exp.replace(expNoParenthesis, ExpressionUtils.doIt(this.edge, rx, ExpressionUtils.parseExpression(expNoParenthesis)));
                  }
               }

               if ((Boolean)evaluator.evaluate(trueFalseWhere)) {
                  rsLst.add(rx);
                  EntityNode sNodex = Main.getEntityNode(rx.getStartNode());
                  if (!this.jg.containsVertex(sNodex)) {
                     this.jg.addVertex(sNodex);
                  }

                  EventEdge e = ExpressionUtils.createEventEdge(sNodex, eNode, rx);
                  if (!this.jg.containsEdge(e)) {
                     this.jg.addEdge(sNodex, eNode, e);
                  }
               }
            }
         }

         Iterator<Relationship> rsIterator = rsLst.iterator();
         return ExpressionUtils.getIterableFromIterator(rsIterator);
      } else {
         String collectExp = this.extractCollectExp(this.expQueue);
         collectExp = collectExp.replaceAll("max\\s*\\(", "max(");
         collectExp = collectExp.replaceAll("min\\s*\\(", "min(");
         String compareProp = collectExp.substring(collectExp.lastIndexOf(46));
         if (!this.srcdstExp.toLowerCase().contains("dst(")) {
            if (this.srcdstExp.toLowerCase().contains("src(")) {
               if (collectExp.contains("max(")) {
                  if (!collectExp.contains("out(")) {
                     collectExp.contains("in(");
                  }
               } else if (collectExp.contains("min(") && !collectExp.contains("out(")) {
                  collectExp.contains("in(");
               }
            }

            return null;
         } else {
            if (collectExp.contains("max(")) {
               if (collectExp.contains("out(")) {
                  List<Long> etLst = new ArrayList<>();
                  if (compareProp.contains("endtime")) {
                     for (Relationship rxx : currentNode.getRelationships(Direction.OUTGOING)) {
                        if (this.isRelationshipIncluded(currentNode, rxx, "outgoing")) {
                           etLst.add((Long)rxx.getProperty("endtime"));
                        }
                     }
                  } else if (compareProp.contains("starttime")) {
                     for (Relationship rxxx : currentNode.getRelationships(Direction.OUTGOING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxx, "outgoing")) {
                           etLst.add((Long)rxxx.getProperty("starttime"));
                        }
                     }
                  }

                  if (etLst.size() > 0) {
                     this.timeMap.putIfAbsent(currentNode, Collections.max(etLst));
                  }
               } else if (collectExp.contains("in(")) {
                  List<Long> etLstx = new ArrayList<>();
                  if (compareProp.contains("endtime")) {
                     for (Relationship rxxxx : currentNode.getRelationships(Direction.INCOMING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxx, "incoming")) {
                           etLstx.add((Long)rxxxx.getProperty("endtime"));
                        }
                     }
                  } else if (compareProp.contains("starttime")) {
                     for (Relationship rxxxxx : currentNode.getRelationships(Direction.INCOMING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxxx, "incoming")) {
                           etLstx.add((Long)rxxxxx.getProperty("starttime"));
                        }
                     }
                  }

                  if (etLstx.size() > 0) {
                     this.timeMap.putIfAbsent(currentNode, Collections.max(etLstx));
                  }
               }
            } else if (collectExp.contains("min(")) {
               if (collectExp.contains("out(")) {
                  List<Long> etLstxx = new ArrayList<>();
                  if (compareProp.contains("endtime")) {
                     for (Relationship rxxxxxx : currentNode.getRelationships(Direction.OUTGOING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxxxx, "outgoing")) {
                           etLstxx.add((Long)rxxxxxx.getProperty("endtime"));
                        }
                     }
                  } else if (compareProp.contains("starttime")) {
                     for (Relationship rxxxxxxx : currentNode.getRelationships(Direction.OUTGOING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxxxxx, "outgoing")) {
                           etLstxx.add((Long)rxxxxxxx.getProperty("starttime"));
                        }
                     }
                  }

                  if (etLstxx.size() > 0) {
                     this.timeMap.putIfAbsent(currentNode, Collections.min(etLstxx));
                  }
               } else if (collectExp.contains("in(")) {
                  List<Long> etLstxxx = new ArrayList<>();
                  if (compareProp.contains("endtime")) {
                     for (Relationship rxxxxxxxx : currentNode.getRelationships(Direction.INCOMING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxxxxxx, "incoming")) {
                           etLstxxx.add((Long)rxxxxxxxx.getProperty("endtime"));
                        }
                     }
                  } else if (compareProp.contains("starttime")) {
                     for (Relationship rxxxxxxxxx : currentNode.getRelationships(Direction.INCOMING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxxxxxxx, "incoming")) {
                           etLstxxx.add((Long)rxxxxxxxxx.getProperty("starttime"));
                        }
                     }
                  }

                  if (etLstxxx.size() > 0) {
                     this.timeMap.putIfAbsent(currentNode, Collections.min(etLstxxx));
                  }
               }
            }

            List<Relationship> rsLst = new ArrayList<>();

            for (Relationship rxxxxxxxxxx : currentNode.getRelationships(Direction.INCOMING)) {
               if (this.isRelationshipIncluded(currentNode, rxxxxxxxxxx, "incoming")) {
                  trueFalseWhere = "";
                  if (this.timeMap.get(rxxxxxxxxxx.getEndNode()) != null) {
                     int index = 0;

                     for (String expx : this.expQueue) {
                        index++;
                        if (expx.contains("collect")) {
                           expx = expx.replaceAll(
                              "(max|min)\\s*\\(.*\\.(endtime|starttime)\\s*((\\)\\s*){2})", this.timeMap.get(rxxxxxxxxxx.getEndNode()).toString()
                           );
                        }

                        String expNoP = expx.replace("(", "").replace(")", "");
                        if (index <= this.expQueue.size() - 1) {
                           trueFalseWhere = trueFalseWhere
                              + expx.replace(expNoP, ExpressionUtils.doIt(this.edge, rxxxxxxxxxx, ExpressionUtils.parseExpression(expNoP)))
                              + " "
                              + this.keyLst.get(index - 1)
                              + " ";
                        } else {
                           trueFalseWhere = trueFalseWhere
                              + expx.replace(expNoP, ExpressionUtils.doIt(this.edge, rxxxxxxxxxx, ExpressionUtils.parseExpression(expNoP)));
                        }
                     }

                     if ((Boolean)evaluator.evaluate(trueFalseWhere)) {
                        rsLst.add(rxxxxxxxxxx);
                        EntityNode sNodexx = Main.getEntityNode(rxxxxxxxxxx.getStartNode());
                        if (!this.jg.containsVertex(sNodexx)) {
                           this.jg.addVertex(sNodexx);
                        }

                        EventEdge e = ExpressionUtils.createEventEdge(sNodexx, eNode, rxxxxxxxxxx);
                        if (!this.jg.containsEdge(e)) {
                           this.jg.addEdge(sNodexx, eNode, e);
                        }
                     }
                  }
               }
            }

            Iterator<Relationship> rsIterator = rsLst.iterator();
            return ExpressionUtils.getIterableFromIterator(rsIterator);
         }
      }
   }

   private boolean isRelationshipIncluded(Node currentNode, Relationship r, String direction) {
      if (direction.equals("incoming")) {
         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.File)
            && "write,writev,rename,modify_file_attributes,create_object".contains(r.getProperty("optype").toString().toLowerCase())) {
            return true;
         }

         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.Process)) {
            if ("execve,execute,clone".contains(r.getProperty("optype").toString().toLowerCase())) {
               return true;
            }

            if ("read,readv,execute,rename".contains(r.getProperty("optype").toString().toLowerCase())) {
               return true;
            }

            if ("recvmsg,recvfrom,read_socket_params,read,readv".contains(r.getProperty("optype").toString().toLowerCase())) {
               return true;
            }
         }

         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.Network)
            && "sendto,sendmsg,write,write_socket_params,connect,writev".contains(r.getProperty("optype").toString().toLowerCase())) {
            return true;
         }
      }

      if (direction.equals("outgoing")) {
         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.File) && "read,readv,execute,rename".contains(r.getProperty("optype").toString().toLowerCase())) {
            return true;
         }

         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.Process)) {
            if ("execve,execute,clone".contains(r.getProperty("optype").toString().toLowerCase())) {
               return true;
            }

            if ("write,writev,rename,modify_file_attributes,create_object".contains(r.getProperty("optype").toString().toLowerCase())) {
               return true;
            }

            if ("sendto,sendmsg,write,write_socket_params,connect,writev".contains(r.getProperty("optype").toString().toLowerCase())) {
               return true;
            }
         }

         if (currentNode.hasLabel(Neo4jTraversal.MyLabel.Network)
            && "recvmsg,recvfrom,read_socket_params,read,readv".contains(r.getProperty("optype").toString().toLowerCase())) {
            return true;
         }
      }

      return false;
   }

   public PathExpander reverse() {
      return null;
   }
}
