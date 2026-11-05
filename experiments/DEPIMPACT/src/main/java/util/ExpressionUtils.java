package util;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Map.Entry;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import model.Edge;
import model.EntityNode;
import model.EventEdge;
import model.Expression;
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.MapContext;
import org.apache.commons.jexl3.JexlException.Variable;
import org.apache.commons.lang3.StringUtils;
import org.neo4j.graphdb.Relationship;

public class ExpressionUtils {
   public static boolean compare(String a1, String a2, BiFunction<Double, Double, Boolean> comparator) {
      double d1 = Double.parseDouble(a1);
      double d2 = Double.parseDouble(a2);
      return comparator.apply(d1, d2);
   }

   public static <A1, A2, R1, R2> R2 compare(A1 a1, A2 a2, BiFunction<A1, A2, R1> func, Function<R1, R2> func2) {
      return func.andThen(func2).apply(a1, a2);
   }

   public static String doIt(Edge edge, Relationship r, Expression e) {
      Long leftVal = 0L;
      Long rightVal = 0L;
      if (e.getLeft().contains(edge.getEdgeName() + ".")) {
         leftVal = (Long)r.getProperty(e.getLeft().substring(e.getLeft().indexOf(".") + 1));
         rightVal = Long.parseLong(e.getRight());
      } else if (e.getRight().contains(edge.getEdgeName() + ".")) {
         rightVal = (Long)r.getProperty(e.getLeft().substring(e.getLeft().indexOf(".") + 1));
         leftVal = Long.parseLong(e.getRight());
      }

      String var6;
      switch ((var6 = e.getOperator()).hashCode()) {
         case 60:
            if (var6.equals("<")) {
               return compare(leftVal, rightVal, (a1, a2) -> a1 < a2, ret -> String.valueOf(ret));
            }
            break;
         case 61:
            if (var6.equals("=")) {
               return compare(leftVal, rightVal, (a1, a2) -> a2, ret -> String.valueOf(ret));
            }
            break;
         case 62:
            if (var6.equals(">")) {
               return compare(leftVal, rightVal, (a1, a2) -> a1 > a2, ret -> String.valueOf(ret));
            }
            break;
         case 1921:
            if (var6.equals("<=")) {
               return compare(leftVal, rightVal, (a1, a2) -> a1 <= a2, ret -> String.valueOf(ret));
            }
            break;
         case 1983:
            if (var6.equals(">=")) {
               return compare(leftVal, rightVal, (a1, a2) -> a1 >= a2, ret -> String.valueOf(ret));
            }
      }

      return "false";
   }

   public static String doIt(Edge edge, ResultSet rs, Expression e) throws SQLException {
      Long leftVal = 0L;
      Long rightVal = 0L;
      if (e.getLeft().contains(edge.getEdgeName() + ".")) {
         leftVal = rs.getLong(e.getLeft().substring(e.getLeft().indexOf(".") + 1));
         rightVal = Long.parseLong(e.getRight());
      } else if (e.getRight().contains(edge.getEdgeName() + ".")) {
         rightVal = rs.getLong(e.getLeft().substring(e.getLeft().indexOf(".") + 1));
         leftVal = Long.parseLong(e.getRight());
      }

      String var6;
      switch ((var6 = e.getOperator()).hashCode()) {
         case 60:
            if (var6.equals("<")) {
               return compare(leftVal, rightVal, (a1, a2) -> a1 < a2, ret -> String.valueOf(ret));
            }
            break;
         case 61:
            if (var6.equals("=")) {
               return compare(leftVal, rightVal, (a1, a2) -> a2, ret -> String.valueOf(ret));
            }
            break;
         case 62:
            if (var6.equals(">")) {
               return compare(leftVal, rightVal, (a1, a2) -> a1 > a2, ret -> String.valueOf(ret));
            }
            break;
         case 1921:
            if (var6.equals("<=")) {
               return compare(leftVal, rightVal, (a1, a2) -> a1 <= a2, ret -> String.valueOf(ret));
            }
            break;
         case 1983:
            if (var6.equals(">=")) {
               return compare(leftVal, rightVal, (a1, a2) -> a1 >= a2, ret -> String.valueOf(ret));
            }
      }

      return "false";
   }

   public static Expression parseExpression(String expression) {
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
         if (!operator.equals(">=") && !operator.equals("<=")) {
            right = expression.substring(operatorIndex + 1);
         } else {
            right = expression.substring(operatorIndex + 2);
         }
      } else {
         if (!operator.equals(">=") && !operator.equals("<=")) {
            right = expression.substring(operatorIndex + 1);
         } else {
            right = expression.substring(operatorIndex + 2);
         }

         left = expression.substring(0, operatorIndex);
      }

      return new Expression(left, operator, right);
   }

   public static <T> Iterable<T> getIterableFromIterator(Iterator<T> iterator) {
      return () -> iterator;
   }

   public static EventEdge createEventEdge(EntityNode srcNode, EntityNode endNode, Relationship r) {
      int eventId = (Integer)r.getProperty("id");
      String opType = r.getProperty("optype").toString();
      Long size = r.hasProperty("amount") ? (Long)r.getProperty("amount") : 0L;
      Long startTime = (Long)r.getProperty("starttime");
      Long endTime = (Long)r.getProperty("endtime");
      String hostName = r.getProperty("hostname").toString();
      EventEdge edge = new EventEdge(srcNode, endNode, (long)eventId, opType, size, startTime, endTime, "", hostName);
      if (r.hasProperty("result") && r.getProperty("result") != null) {
         edge.setResult(((Number)r.getProperty("result")).longValue());
      }
      return edge;
   }

   public static EventEdge createEventEdge(EntityNode srcNode, EntityNode endNode, ResultSet rs) throws SQLException {
      Long eventId = rs.getLong("eventid");
      String opType = rs.getString("optype");
      Long size = rs.getLong("amount");
      Long startTime = rs.getLong("starttime");
      Long endTime = rs.getLong("endtime");
      String hostName = rs.getString("hostname");
      EventEdge edge = new EventEdge(srcNode, endNode, eventId, opType, size, startTime, endTime, "", hostName);
      // result 可能是 null（accept/create/clone 等无返回值的边），也可能是 Integer/Long。
      Object resultValue = rs.getObject("result");
      if (resultValue instanceof Number) {
         edge.setResult(((Number)resultValue).longValue());
      }
      return edge;
   }

   public static String extractCollectExp(Queue<String> expQueue) {
      String collectExp = "";

      for (String exp : expQueue) {
         if (exp.contains("collect")) {
            collectExp = exp;
            break;
         }
      }

      return collectExp;
   }

   public static void extractOperatorAndValue(String expression, StringBuilder operator, StringBuilder value) {
      Pattern pattern = Pattern.compile("([=><]+)([0-9]+)");
      Matcher matcher = pattern.matcher(expression);
      if (matcher.find()) {
         operator.setLength(0);
         operator.append(matcher.group(1));
         value.setLength(0);
         value.append(matcher.group(2));
      }
   }

   public static Object evaluateExpression(String expression, Map<String, Long> values) {
      JexlEngine jexl = new JexlBuilder().create();
      JexlExpression jexlExpression = jexl.createExpression(expression);
      JexlContext context = new MapContext();

      for (Entry<String, Long> entry : values.entrySet()) {
         context.set(entry.getKey(), entry.getValue());
      }

      try {
         return jexlExpression.evaluate(context);
      } catch (Variable var7) {
         System.err.println("Undefined variable: " + var7.getVariable());
         return null;
      }
   }

   public static String replaceEqualsWithNumericComparison(String expression, Map<String, Long> values) {
      for (Entry<String, Long> entry : values.entrySet()) {
         expression = expression.replace(entry.getKey() + "= ", "numericEquals(" + entry.getKey() + ", ");
      }

      return expression;
   }

   public static Queue<String> extractExpFromWhere(String whereString) {
      whereString = whereString.toLowerCase().replaceAll("where\\s*", "");
      Queue<String> expQueue = new LinkedList<>();

      String[] var5;
      for (String expStr : var5 = whereString.split("(and)|(or)")) {
         expStr = StringUtils.normalizeSpace(expStr);
         expQueue.add(expStr.trim());
      }

      return expQueue;
   }

   public static List<String> extractKeyFromWhere(String whereString) {
      whereString = whereString.toUpperCase();
      List<String> keyLst = new ArrayList<>();
      String[] words = whereString.split(" ");

      for (String word : words) {
         if (word.equals("AND") || word.equals("OR")) {
            keyLst.add(word);
         }
      }

      return keyLst;
   }
}
