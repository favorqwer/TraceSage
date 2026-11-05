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

public class ForwardExpander implements PathExpander {
   private Queue<String> expQueue = new LinkedList<>();
   private List<String> keyLst = new ArrayList<>();
   private Edge edge;
   private String srcdstExp;
   private DirectedPseudograph<EntityNode, EventEdge> jg;
   private static AbstractEvaluator<Boolean> evaluator = new TextualOperatorsEvaluator();
   private HashMap<Node, Long> maxTimeMap = new HashMap<>();
   private HashMap<Node, Long> minTimeMap = new HashMap<>();

   public ForwardExpander(Edge edge, Queue<String> expQueue, List<String> keyLst, String srcdstExp, DirectedPseudograph<EntityNode, EventEdge> jg) {
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

   public Iterable expand(Path path, BranchState state) {
      String trueFalseWhere = "";
      int depth = path.length();
      Node currentNode = path.endNode();
      EntityNode sNode = Main.getEntityNode(currentNode);
      if (!this.jg.containsVertex(sNode)) {
         this.jg.addVertex(sNode);
      }

      if (this.expQueue.size() == 0) {
         List<Relationship> rsLst = new ArrayList<>();

         for (Relationship r : currentNode.getRelationships(Direction.OUTGOING)) {
            if (this.isRelationshipIncluded(currentNode, r, "outgoing")) {
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

         Iterator<Relationship> rsIterator = rsLst.iterator();
         return ExpressionUtils.getIterableFromIterator(rsIterator);
      } else if (this.extractCollectExp(this.expQueue).isEmpty()) {
         List<Relationship> rsLst = new ArrayList<>();

         for (Relationship rx : currentNode.getRelationships(Direction.OUTGOING)) {
            if (this.isRelationshipIncluded(currentNode, rx, "outgoing")) {
               trueFalseWhere = "";
               int index = 0;

               for (String exp : this.expQueue) {
                  index++;
                  String expNoP = exp.replace("(", "").replace(")", "");
                  if (index <= this.expQueue.size() - 1) {
                     trueFalseWhere = trueFalseWhere
                        + exp.replace(expNoP, ExpressionUtils.doIt(this.edge, rx, ExpressionUtils.parseExpression(expNoP)))
                        + " "
                        + this.keyLst.get(index - 1)
                        + " ";
                  } else {
                     trueFalseWhere = trueFalseWhere + exp.replace(expNoP, ExpressionUtils.doIt(this.edge, rx, ExpressionUtils.parseExpression(expNoP)));
                  }
               }

               if ((Boolean)evaluator.evaluate(trueFalseWhere)) {
                  rsLst.add(rx);
                  EntityNode eNodex = Main.getEntityNode(rx.getEndNode());
                  if (!this.jg.containsVertex(eNodex)) {
                     this.jg.addVertex(eNodex);
                  }

                  EventEdge e = ExpressionUtils.createEventEdge(sNode, eNodex, rx);
                  if (!this.jg.containsEdge(e)) {
                     this.jg.addEdge(sNode, eNodex, e);
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
         if (this.srcdstExp.toLowerCase().contains("src(")) {
            if (collectExp.contains("min(")) {
               if (collectExp.contains("in(")) {
                  List<Long> stLst = new ArrayList<>();
                  if (compareProp.contains("starttime")) {
                     for (Relationship rxx : currentNode.getRelationships(Direction.INCOMING)) {
                        if (this.isRelationshipIncluded(currentNode, rxx, "incoming")) {
                           stLst.add((Long)rxx.getProperty("starttime"));
                        }
                     }
                  } else if (compareProp.contains("endtime")) {
                     for (Relationship rxxx : currentNode.getRelationships(Direction.INCOMING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxx, "incoming")) {
                           stLst.add((Long)rxxx.getProperty("endtime"));
                        }
                     }
                  }

                  if (stLst.size() > 0) {
                     this.minTimeMap.putIfAbsent(currentNode, Collections.min(stLst));
                  }
               } else if (collectExp.contains("out(")) {
                  List<Long> stLstx = new ArrayList<>();
                  if (compareProp.contains("starttime")) {
                     for (Relationship rxxxx : currentNode.getRelationships(Direction.OUTGOING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxx, "outgoing")) {
                           stLstx.add((Long)rxxxx.getProperty("starttime"));
                        }
                     }
                  } else if (compareProp.contains("endtime")) {
                     for (Relationship rxxxxx : currentNode.getRelationships(Direction.OUTGOING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxxx, "outgoing")) {
                           stLstx.add((Long)rxxxxx.getProperty("endtime"));
                        }
                     }
                  }

                  if (stLstx.size() > 0) {
                     this.minTimeMap.putIfAbsent(currentNode, Collections.min(stLstx));
                  }
               }

               List<Relationship> rsLst = new ArrayList<>();

               for (Relationship rxxxxxx : currentNode.getRelationships(Direction.OUTGOING)) {
                  if (this.isRelationshipIncluded(currentNode, rxxxxxx, "outgoing")) {
                     trueFalseWhere = "";
                     if (this.minTimeMap.get(rxxxxxx.getStartNode()) != null) {
                        int index = 0;

                        for (String expx : this.expQueue) {
                           index++;
                           if (expx.contains("collect")) {
                              expx = expx.replaceAll(
                                 "(max|min)\\s*\\(.*\\.(endtime|starttime)\\s*((\\)\\s*){2})", this.minTimeMap.get(rxxxxxx.getStartNode()).toString()
                              );
                           }

                           String expNoP = expx.replace("(", "").replace(")", "");
                           if (index <= this.expQueue.size() - 1) {
                              trueFalseWhere = trueFalseWhere
                                 + expx.replace(expNoP, ExpressionUtils.doIt(this.edge, rxxxxxx, ExpressionUtils.parseExpression(expNoP)))
                                 + " "
                                 + this.keyLst.get(index - 1)
                                 + " ";
                           } else {
                              trueFalseWhere = trueFalseWhere
                                 + expx.replace(expNoP, ExpressionUtils.doIt(this.edge, rxxxxxx, ExpressionUtils.parseExpression(expNoP)));
                           }
                        }

                        if ((Boolean)evaluator.evaluate(trueFalseWhere)) {
                           rsLst.add(rxxxxxx);
                           EntityNode eNodexx = Main.getEntityNode(rxxxxxx.getEndNode());
                           this.jg.addVertex(eNodexx);
                           EventEdge e = ExpressionUtils.createEventEdge(sNode, eNodexx, rxxxxxx);
                           if (!this.jg.containsEdge(e)) {
                              this.jg.addEdge(sNode, eNodexx, e);
                           }
                        }
                     }
                  }
               }

               Iterator<Relationship> rsIterator = rsLst.iterator();
               return ExpressionUtils.getIterableFromIterator(rsIterator);
            }

            if (collectExp.contains("max(")) {
               if (collectExp.contains("in(")) {
                  List<Long> stLstxx = new ArrayList<>();
                  if (compareProp.contains("starttime")) {
                     for (Relationship rxxxxxxx : currentNode.getRelationships(Direction.INCOMING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxxxxx, "incoming")) {
                           stLstxx.add((Long)rxxxxxxx.getProperty("starttime"));
                        }
                     }
                  } else if (compareProp.contains("endtime")) {
                     for (Relationship rxxxxxxxx : currentNode.getRelationships(Direction.INCOMING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxxxxxx, "incoming")) {
                           stLstxx.add((Long)rxxxxxxxx.getProperty("endtime"));
                        }
                     }
                  }

                  if (stLstxx.size() > 0) {
                     this.maxTimeMap.putIfAbsent(currentNode, Collections.max(stLstxx));
                  }
               } else if (collectExp.contains("out(")) {
                  List<Long> stLstxxx = new ArrayList<>();
                  if (compareProp.contains("starttime")) {
                     for (Relationship rxxxxxxxxx : currentNode.getRelationships(Direction.OUTGOING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxxxxxxx, "outgoing")) {
                           stLstxxx.add((Long)rxxxxxxxxx.getProperty("starttime"));
                        }
                     }
                  } else if (compareProp.contains("endtime")) {
                     for (Relationship rxxxxxxxxxx : currentNode.getRelationships(Direction.OUTGOING)) {
                        if (this.isRelationshipIncluded(currentNode, rxxxxxxxxxx, "outgoing")) {
                           stLstxxx.add((Long)rxxxxxxxxxx.getProperty("endtime"));
                        }
                     }
                  }

                  if (stLstxxx.size() > 0) {
                     this.maxTimeMap.putIfAbsent(currentNode, Collections.max(stLstxxx));
                  }
               }

               List<Relationship> rsLst = new ArrayList<>();

               for (Relationship rxxxxxxxxxxx : currentNode.getRelationships(Direction.OUTGOING)) {
                  if (this.isRelationshipIncluded(currentNode, rxxxxxxxxxxx, "outgoing")) {
                     trueFalseWhere = "";
                     if (this.maxTimeMap.get(rxxxxxxxxxxx.getStartNode()) != null) {
                        int index = 0;

                        for (String expx : this.expQueue) {
                           index++;
                           if (expx.contains("collect")) {
                              expx = expx.replaceAll(
                                 "(max|min)\\s*\\(.*\\.(endtime|starttime)\\s*((\\)\\s*){2})", this.maxTimeMap.get(rxxxxxxxxxxx.getStartNode()).toString()
                              );
                           }

                           String expNoP = expx.replace("(", "").replace(")", "");
                           if (index <= this.expQueue.size() - 1) {
                              trueFalseWhere = trueFalseWhere
                                 + expx.replace(expNoP, ExpressionUtils.doIt(this.edge, rxxxxxxxxxxx, ExpressionUtils.parseExpression(expNoP)))
                                 + " "
                                 + this.keyLst.get(index - 1)
                                 + " ";
                           } else {
                              trueFalseWhere = trueFalseWhere
                                 + expx.replace(expNoP, ExpressionUtils.doIt(this.edge, rxxxxxxxxxxx, ExpressionUtils.parseExpression(expNoP)));
                           }
                        }

                        if ((Boolean)evaluator.evaluate(trueFalseWhere)) {
                           rsLst.add(rxxxxxxxxxxx);
                           EntityNode eNodexx = Main.getEntityNode(rxxxxxxxxxxx.getEndNode());
                           this.jg.addVertex(eNodexx);
                           EventEdge e = ExpressionUtils.createEventEdge(sNode, eNodexx, rxxxxxxxxxxx);
                           if (!this.jg.containsEdge(e)) {
                              this.jg.addEdge(sNode, eNodexx, e);
                           }
                        }
                     }
                  }
               }

               Iterator<Relationship> rsIterator = rsLst.iterator();
               return ExpressionUtils.getIterableFromIterator(rsIterator);
            }
         } else if (this.srcdstExp.toLowerCase().contains("dst(")) {
            if (collectExp.contains("min(")) {
               if (!collectExp.contains("in(")) {
                  collectExp.contains("out(");
               }
            } else if (collectExp.contains("max(") && !collectExp.contains("in(")) {
               collectExp.contains("out(");
            }
         }

         return null;
      }
   }

   public PathExpander reverse() {
      return null;
   }
}
