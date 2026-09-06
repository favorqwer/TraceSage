package util;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.MapContext;
import org.apache.commons.jexl3.JexlException.Variable;

public class LogicalExpressionEvaluator {
   public static String evaluateLogicalExpression(String input) {
      try {
         ScriptEngineManager manager = new ScriptEngineManager();
         ScriptEngine engine = manager.getEngineByName("js");
         String modifiedInput = input.replaceAll("<", "<=");
         modifiedInput = modifiedInput.replaceAll("\\band\\b", "&&");
         modifiedInput = modifiedInput.replaceAll("\\bor\\b", "||");
         Object result = engine.eval(modifiedInput);
         return String.valueOf(result);
      } catch (ScriptException var6) {
         var6.printStackTrace();
         return "Error evaluating the expression";
      }
   }

   public static void extractOperatorAndValue(String expression) {
      Pattern pattern = Pattern.compile("([=><]+)([0-9]+)");
      Matcher matcher = pattern.matcher(expression);
      if (matcher.find()) {
         String operator = matcher.group(1);
         String value = matcher.group(2);
         System.out.println("Expression: " + expression);
         System.out.println("Operator: " + operator);
         System.out.println("Value: " + value);
         System.out.println();
      } else {
         System.out.println("No match found for expression: " + expression);
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

   private static String replaceEqualsWithNumericComparison(String expression, Map<String, Long> values) {
      for (Entry<String, Long> entry : values.entrySet()) {
         expression = expression.replace(entry.getKey() + "= ", "numericEquals(" + entry.getKey() + ", ");
      }

      return expression;
   }

   public static void main(String[] args) {
      Map<String, Long> propertyValues = new HashMap<>();
      propertyValues.put("r.starttime", 1523385317249665654L);
      propertyValues.putIfAbsent("r.starttime", 1523385317249665650L);
      propertyValues.put("r.endtime", 1523385317249665660L);
      propertyValues.put("r.type", 1523385317249665655L);
      System.out.println(propertyValues.get("r.starttime"));
      String expression = "r.starttime<1523385317249665680 and (r.endtime>1523385317249665659 and r.type==1523385317249665656)";
      expression = replaceEqualsWithNumericComparison(expression, propertyValues);
      Object result = evaluateExpression(expression, propertyValues);
      System.out.println("* " + result);
      if ((Boolean)result) {
         System.out.println("+ " + result);
      } else {
         System.out.println("- " + result);
      }
   }
}
