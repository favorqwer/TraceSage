package util;

import com.fathzer.soft.javaluator.AbstractEvaluator;
import com.fathzer.soft.javaluator.DoubleEvaluator;
import com.fathzer.soft.javaluator.Operator;
import com.fathzer.soft.javaluator.Parameters;
import com.fathzer.soft.javaluator.StaticVariableSet;
import com.fathzer.soft.javaluator.Operator.Associativity;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import model.Expression;

public class TextualOperatorsEvaluator extends AbstractEvaluator<Boolean> {
   public static final Operator NEGATE = new Operator("NOT", 1, Associativity.RIGHT, 3);
   private static final Operator AND = new Operator("AND", 2, Associativity.LEFT, 2);
   public static final Operator OR = new Operator("OR", 2, Associativity.LEFT, 1);
   private static final Parameters PARAMETERS = new Parameters();

   static {
      PARAMETERS.add(AND);
      PARAMETERS.add(OR);
      PARAMETERS.add(NEGATE);
   }

   public TextualOperatorsEvaluator() {
      super(PARAMETERS);
   }

   protected Boolean toValue(String literal, Object evaluationContext) {
      int index = literal.indexOf(61);
      if (index >= 0) {
         String variable = literal.substring(0, index);
         String value = literal.substring(index + 1);
         return value.equals(((Map)evaluationContext).get(variable));
      } else {
         return Boolean.valueOf(literal);
      }
   }

   protected Boolean evaluate(Operator operator, Iterator<Boolean> operands, Object evaluationContext) {
      if (operator == NEGATE) {
         return !operands.next();
      } else if (operator == OR) {
         Boolean o1 = operands.next();
         Boolean o2 = operands.next();
         return !o1 && !o2 ? false : true;
      } else if (operator == AND) {
         Boolean o1 = operands.next();
         Boolean o2 = operands.next();
         return o1 && o2 ? true : false;
      } else {
         return (Boolean)super.evaluate(operator, operands, evaluationContext);
      }
   }

   protected Iterator<String> tokenize(String expression) {
      return Arrays.asList(expression.split("\\s")).iterator();
   }

   public static void main(String[] args) {
      AbstractEvaluator<Boolean> evaluator = new TextualOperatorsEvaluator();
      System.out.println("Hello -> " + evaluator.evaluate("true AND true"));
      System.out.println("Hello -> " + evaluator.evaluate("true AND (true OR False) AND False"));
      String whereClause = "True AND (False OR (False AND True))";
      String[] someArray = whereClause.split("(AND)|(OR)");
      Queue<String> expQueue = new LinkedList<>();

      for (String s : someArray) {
         System.out.println(s.trim());
         expQueue.add(s.trim());
      }

      List<String> keyLst = new ArrayList<>();
      String[] words = whereClause.split(" ");

      for (String word : words) {
         if (word.equals("AND") || word.equals("OR")) {
            keyLst.add(word);
         }
      }

      String restoreWhere = "";
      int index = 0;

      for (String exp : expQueue) {
         if (++index <= expQueue.size() - 1) {
            restoreWhere = restoreWhere + exp + " " + keyLst.get(index - 1) + " ";
         } else {
            restoreWhere = restoreWhere + exp;
         }
      }

      Boolean retVal;
      label63: {
         System.out.println(restoreWhere);
         DoubleEvaluator eval = new DoubleEvaluator();
         String expression = "abs(r.amount + r.amount - st.amount)";
         StaticVariableSet<Double> variables = new StaticVariableSet();
         variables.set("r.amount", 5.0);
         variables.set("r.amount", 6.0);
         variables.set("st.amount", 10.0);
         System.out.println(variables.get("r.amount"));
         Double result = (Double)eval.evaluate(expression, variables);
         System.out.println("*************" + result);
         String expression2 = "ln(1+1/abs(r.endtime-st.endtime))";
         StaticVariableSet<Double> variables2 = new StaticVariableSet();
         variables2.set("r.endtime", new BigDecimal("1679364477932300947".substring(0, 10) + "." + "1679364477932300947".substring(10)).doubleValue());
         variables2.set("st.endtime", new BigDecimal("1679364486000959259".substring(0, 10) + "." + "1679364486000959259".substring(10)).doubleValue());
         Double result2 = (Double)eval.evaluate(expression2, variables2);
         System.out.println("----------------" + result2);
         String evalExpr = "e.weight >= 0.5";
         Expression expr = ExpressionUtils.parseExpression(evalExpr);
         String leftVal = expr.getLeft();
         String operator = expr.getOperator();
         String rightVal = expr.getRight();
         String replacedLeft = isNumeric(leftVal) ? leftVal : "0.4";
         String replacedRight = isNumeric(rightVal) ? rightVal : "0.4";
         String newExpression = replacedLeft + " " + operator + " " + replacedRight;
         switch (operator.hashCode()) {
            case 60:
               if (operator.equals("<")) {
                  retVal = ExpressionUtils.compare(replacedLeft, replacedRight, (a1, a2) -> a1 < a2);
                  break label63;
               }
               break;
            case 61:
               if (operator.equals("=")) {
                  retVal = ExpressionUtils.compare(replacedLeft, replacedRight, (a1, a2) -> a1 == a2);
                  break label63;
               }
               break;
            case 62:
               if (operator.equals(">")) {
                  retVal = ExpressionUtils.compare(replacedLeft, replacedRight, (a1, a2) -> a1 > a2);
                  break label63;
               }
               break;
            case 1921:
               if (operator.equals("<=")) {
                  retVal = ExpressionUtils.compare(replacedLeft, replacedRight, (a1, a2) -> a1 <= a2);
                  break label63;
               }
               break;
            case 1983:
               if (operator.equals(">=")) {
                  retVal = ExpressionUtils.compare(replacedLeft, replacedRight, (a1, a2) -> a1 >= a2);
                  break label63;
               }
         }

         retVal = false;
      }

      System.out.println("++++++++++++++++" + retVal);
      long time = 1679361216023335923L;
      BigDecimal timeS = new BigDecimal(time / 1000000000L);
      System.out.println(timeS);
      String pattern = "neo4j-community-3.5.11/data/databases/theia.db";
      System.out.println(pattern.substring(pattern.lastIndexOf(47) + 1, pattern.lastIndexOf(46)));
      String pattern1 = "^(?:(?!/proc/|/usr/lib/|/lib/x86_64-linux-gnu|/usr/lib/python3.7/|/usr/share/|/usr/local/).)*$";
      boolean doesNotContain = Pattern.matches(pattern1, "/home/feishao/sysrep_test_temp/python_write_random_data.py");
      System.out.println("Does not contain: " + doesNotContain);
      List<String> a = Arrays.asList("A1", "A2", "A3");
      List<String> b = Arrays.asList("B1", "B2");
      List<String> c = Arrays.asList("C1", "C2", "C3");
      List<String> result3 = pickElementsInTurns(a, b, c);
      System.out.println(result3);
      String patternExcludeLib = "^(?:(?!/proc/|/usr/lib/|/lib/x86_64-linux-gnu|/usr/lib/python3.7/|/usr/share/|/usr/local/).)*$";
      String patternIncludeLib = "^(/proc/|/usr/lib/|/lib/x86_64-linux-gnu|/usr/lib/python3.7/|/usr/share/|/usr/local/).*";
      System.out.println("*#%$^%&%%% " + Pattern.matches(patternIncludeLib, "/usr/lib/python3.7/encodings/__pycache__/latin_1.cpython-37.pyc"));
      System.out.println("*#%$^%&%%% " + Pattern.matches(patternIncludeLib, "/home/feishao/sysrep_test_temp/python_write_random_data.py"));
      String s = "\"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\NGenTask.exe\" /RuntimeWide /StopEvent:460";
      s = replaceQuotes(s);
      System.out.println(s);
      String originalJsonString = "{exename: \"\"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\NGenTask.exe\" /RuntimeWide /StopEvent:460\", hostname: \"RiseLab\", ownergroupid: \"\", owneruserid: \"\", pid: 7608, uuid: \"E371E8B6-938E-4F62-B321-78725409D145\"}";
      String ss = "{dstip: \"208.\"75.117.5\"/32\", dstport: 80, hostname: \"RiseLab\", srcip: \"128.55.12.67/32\", srcport: 57619, uuid: \"A2228FBE-118E-44C1-8D52-0A66D3CC12AC\"}";
      Map<String, String> resultMap = convertToMap(ss);
      System.out.println("Resulting Map:");

      for (Entry<String, String> entry : resultMap.entrySet()) {
         System.out.println("Key: " + entry.getKey() + ", Value: " + entry.getValue());
      }

      System.out.println("1523643618976000000".substring(0, 10) + "." + "1523643618976000000".substring(10));
   }

   private static boolean isNumeric(String str) {
      if (str == null) {
         return false;
      } else {
         try {
            Double.parseDouble(str);
            return true;
         } catch (NumberFormatException var2) {
            return false;
         }
      }
   }

   public static String replaceQuotes(String input) {
      return input.replace("\"", "");
   }

   public static String removeInnerDoubleQuotes(String input) {
      String regex = "(\"(?:[^\"\\\\]|\\\\.)+\")";
      Pattern pattern = Pattern.compile(regex);
      Matcher matcher = pattern.matcher(input);
      StringBuffer result = new StringBuffer();

      while (matcher.find()) {
         matcher.appendReplacement(result, matcher.group().replace("\"", ""));
      }

      matcher.appendTail(result);
      return result.toString();
   }

   public static Map<String, String> convertToMap(String input) {
      Map<String, String> resultMap = new HashMap<>();
      Pattern pattern = Pattern.compile("\\s*([a-zA-Z_]+)\\s*:\\s*\"?([^\",]+)\"?\\s*");
      Matcher matcher = pattern.matcher(input);

      while (matcher.find()) {
         String key = matcher.group(1);
         String value = matcher.group(2);
         resultMap.put(key, value);
      }

      return resultMap;
   }

   private static <T> List<T> pickElementsInTurns(List<T>... lists) {
      List<T> result = new ArrayList<>();
      Iterator[] iterators = new Iterator[lists.length];

      for (int i = 0; i < lists.length; i++) {
         iterators[i] = lists[i].iterator();
      }

      while (hasNext(iterators)) {
         for (Iterator<T> iterator : iterators) {
            if (iterator.hasNext()) {
               result.add(iterator.next());
            }
         }
      }

      return result;
   }

   private static <T> boolean hasNext(Iterator<T>[] iterators) {
      for (Iterator<T> iterator : iterators) {
         if (iterator.hasNext()) {
            return true;
         }
      }

      return false;
   }
}
