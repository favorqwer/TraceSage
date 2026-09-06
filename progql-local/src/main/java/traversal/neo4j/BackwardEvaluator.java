package traversal.neo4j;

import com.fathzer.soft.javaluator.AbstractEvaluator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Queue;
import java.util.function.BiFunction;
import java.util.function.Function;
import model.Edge;
import model.Expression;
import org.neo4j.graphdb.Direction;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Path;
import org.neo4j.graphdb.Relationship;
import org.neo4j.graphdb.traversal.Evaluation;
import org.neo4j.graphdb.traversal.Evaluator;
import util.TextualOperatorsEvaluator;

public class BackwardEvaluator implements Evaluator {
   private Queue<String> whereQueue = new LinkedList<>();
   private Edge edge;
   private Boolean hasCollectCondition;
   private long maxEndtimeOfActualPOI;
   private HashMap<Node, Long> maxEndtimeMap = new HashMap<>();
   private static AbstractEvaluator<Boolean> evaluator = new TextualOperatorsEvaluator();

   public BackwardEvaluator(Edge edge, Queue<String> whereQueue, Boolean hasCollectCondition, long maxEndtimeOfActualPOI) {
      this.edge = edge;
      this.whereQueue = whereQueue;
      this.hasCollectCondition = hasCollectCondition;
      this.maxEndtimeOfActualPOI = maxEndtimeOfActualPOI;
   }

   private <A1, A2, R1, R2> R2 compare(A1 a1, A2 a2, BiFunction<A1, A2, R1> func, Function<R1, R2> func2) {
      return func.andThen(func2).apply(a1, a2);
   }

   private String doIt(Relationship r, Expression e) {
      Long leftVal = 0L;
      Long rightVal = 0L;
      if (e.getLeft().contains(this.edge.getEdgeName() + ".")) {
         leftVal = (Long)r.getProperty(e.getLeft().substring(e.getLeft().indexOf(".") + 1));
         rightVal = Long.parseLong(e.getRight());
      } else if (e.getRight().contains(this.edge.getEdgeName() + ".")) {
         rightVal = (Long)r.getProperty(e.getLeft().substring(e.getLeft().indexOf(".") + 1));
         leftVal = Long.parseLong(e.getRight());
      }

      String var6;
      switch ((var6 = e.getOperator()).hashCode()) {
         case 60:
            if (var6.equals("<")) {
               return this.compare(leftVal, rightVal, (a1, a2) -> a1 < a2, ret -> String.valueOf(ret));
            }
            break;
         case 61:
            if (var6.equals("=")) {
               return this.compare(leftVal, rightVal, (a1, a2) -> a2, ret -> String.valueOf(ret));
            }
            break;
         case 62:
            if (var6.equals(">")) {
               return this.compare(leftVal, rightVal, (a1, a2) -> a1 > a2, ret -> String.valueOf(ret));
            }
            break;
         case 1921:
            if (var6.equals("<=")) {
               return this.compare(leftVal, rightVal, (a1, a2) -> a1 <= a2, ret -> String.valueOf(ret));
            }
            break;
         case 1983:
            if (var6.equals(">=")) {
               return this.compare(leftVal, rightVal, (a1, a2) -> a1 >= a2, ret -> String.valueOf(ret));
            }
      }

      return "false";
   }

   private Expression parseExpression(String expression) {
      int dotIndex = expression.indexOf(46);
      int operatorIndex = 0;
      String left = "";
      String operator = "";
      String right = "";
      Expression e = null;
      if (expression.contains(">") && !expression.contains(">=")) {
         operator = ">";
         operatorIndex = expression.indexOf(">");
      } else if (expression.contains(">=")) {
         operator = ">=";
         operatorIndex = expression.indexOf(">=");
      } else if (expression.contains("<") && !expression.contains("<=")) {
         operator = "<";
         operatorIndex = expression.indexOf("<");
      } else if (expression.contains("<=")) {
         operator = "<=";
         operatorIndex = expression.indexOf("<=");
      } else if (expression.contains("=")) {
         operator = "=";
         operatorIndex = expression.indexOf("=");
      }

      if (dotIndex < operatorIndex) {
         left = expression.substring(0, operatorIndex);
         right = expression.substring(operatorIndex + 1);
      } else {
         right = expression.substring(operatorIndex + 1);
         left = expression.substring(0, operatorIndex);
      }

      return new Expression(left, operator, right);
   }

   public Evaluation evaluate(Path path) {
      String trueFalseWhere = "";
      Node currentNode = path.endNode();
      if (this.whereQueue.size() == 0) {
         return Evaluation.INCLUDE_AND_CONTINUE;
      } else {
         if (!this.hasCollectCondition) {
            Iterator r = currentNode.getRelationships(Direction.OUTGOING).iterator();
            if (r.hasNext()) {
               Relationship rx = (Relationship)r.next();
               if (path.length() == 0) {
                  return Evaluation.INCLUDE_AND_CONTINUE;
               }

               for (String exp : this.whereQueue) {
                  if (!exp.equals("AND") && !exp.equals("OR")) {
                     trueFalseWhere = trueFalseWhere + this.doIt(rx, this.parseExpression(exp)) + " ";
                  } else {
                     trueFalseWhere = trueFalseWhere + exp + " ";
                  }
               }

               if (trueFalseWhere.endsWith("AND ")) {
                  trueFalseWhere = trueFalseWhere.substring(0, trueFalseWhere.length() - 4);
               }

               if (trueFalseWhere.endsWith("OR ")) {
                  trueFalseWhere = trueFalseWhere.substring(0, trueFalseWhere.length() - 3);
               }

               if (trueFalseWhere.startsWith("AND ")) {
                  trueFalseWhere = trueFalseWhere.substring(4);
               }

               if (trueFalseWhere.startsWith("OR ")) {
                  trueFalseWhere = trueFalseWhere.substring(3);
               }

               if ((Boolean)evaluator.evaluate(trueFalseWhere)) {
                  return Evaluation.INCLUDE_AND_CONTINUE;
               }

               return Evaluation.EXCLUDE_AND_CONTINUE;
            }
         } else {
            Long endTime = this.maxEndtimeOfActualPOI;

            for (Relationship rx : currentNode.getRelationships(Direction.OUTGOING)) {
               if (path.length() > 0) {
                  Long et = (Long)rx.getProperty("endtime");
                  endTime = et > endTime ? et : endTime;
               }
            }

            this.maxEndtimeMap.putIfAbsent(currentNode, endTime);
            Iterator var14 = currentNode.getRelationships(Direction.OUTGOING).iterator();
            if (var14.hasNext()) {
               Relationship rxx = (Relationship)var14.next();
               if (path.length() == 0) {
                  return Evaluation.INCLUDE_AND_CONTINUE;
               }

               Long st = (Long)rxx.getProperty("starttime");
               if (this.maxEndtimeMap.get(rxx.getEndNode()) == null) {
                  return Evaluation.EXCLUDE_AND_CONTINUE;
               }

               for (String expx : this.whereQueue) {
                  if (!expx.toLowerCase().contains("collect")) {
                     if (!expx.equals("AND") && !expx.equals("OR")) {
                        trueFalseWhere = trueFalseWhere + this.doIt(rxx, this.parseExpression(expx)) + " ";
                     } else {
                        trueFalseWhere = trueFalseWhere + expx + " ";
                     }
                  }
               }

               if (trueFalseWhere.endsWith("AND ")) {
                  trueFalseWhere = trueFalseWhere.substring(0, trueFalseWhere.length() - 4);
               }

               if (trueFalseWhere.endsWith("OR ")) {
                  trueFalseWhere = trueFalseWhere.substring(0, trueFalseWhere.length() - 3);
               }

               if (trueFalseWhere.startsWith("AND ")) {
                  trueFalseWhere = trueFalseWhere.substring(4);
               }

               if (trueFalseWhere.startsWith("OR ")) {
                  trueFalseWhere = trueFalseWhere.substring(3);
               }

               if (!trueFalseWhere.isEmpty()) {
                  if (st < this.maxEndtimeMap.get(rxx.getEndNode()) && (Boolean)evaluator.evaluate(trueFalseWhere)) {
                     return Evaluation.INCLUDE_AND_CONTINUE;
                  }

                  return Evaluation.EXCLUDE_AND_CONTINUE;
               }

               if (st < this.maxEndtimeMap.get(rxx.getEndNode())) {
                  return Evaluation.INCLUDE_AND_CONTINUE;
               }

               return Evaluation.EXCLUDE_AND_CONTINUE;
            }
         }

         return Evaluation.INCLUDE_AND_CONTINUE;
      }
   }
}
