package util;

import com.fathzer.soft.javaluator.AbstractEvaluator;
import com.fathzer.soft.javaluator.BracketPair;
import com.fathzer.soft.javaluator.Operator;
import com.fathzer.soft.javaluator.Parameters;
import com.fathzer.soft.javaluator.Operator.Associativity;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class TreeBooleanEvaluator extends AbstractEvaluator<String> {
   private static final Operator AND = new Operator("AND", 2, Associativity.LEFT, 2);
   public static final Operator OR = new Operator("OR", 2, Associativity.LEFT, 1);
   private static final Parameters PARAMETERS = new Parameters();

   static {
      PARAMETERS.add(AND);
      PARAMETERS.add(OR);
      PARAMETERS.addExpressionBracket(BracketPair.PARENTHESES);
   }

   public TreeBooleanEvaluator() {
      super(PARAMETERS);
   }

   protected String toValue(String literal, Object evaluationContext) {
      return literal;
   }

   private boolean getValue(String literal) {
      if ("T".equals(literal) || literal.endsWith("=true")) {
         return true;
      } else if (!"F".equals(literal) && !literal.endsWith("=false")) {
         throw new IllegalArgumentException("Unknown literal : " + literal);
      } else {
         return false;
      }
   }

   protected String evaluate(Operator operator, Iterator<String> operands, Object evaluationContext) {
      List<String> tree = (List<String>)evaluationContext;
      String o1 = operands.next();
      String o2 = operands.next();
      Boolean result;
      if (operator == OR) {
         result = this.getValue(o1) || this.getValue(o2);
      } else {
         if (operator != AND) {
            throw new IllegalArgumentException();
         }

         result = this.getValue(o1) && this.getValue(o2);
      }

      String eval = "(" + o1 + " " + operator.getSymbol() + " " + o2 + ")=" + result;
      tree.add(eval);
      return eval;
   }

   public static void main(String[] args) {
      TreeBooleanEvaluator evaluator = new TreeBooleanEvaluator();
      doIt(evaluator, "T AND (F OR (F AND T))");
      doIt(evaluator, "(T AND T) OR (F AND T)");
      doIt(evaluator, "T AND T OR F AND F");
      doIt(evaluator, "T AND (T OR F) AND F");
   }

   private static void doIt(TreeBooleanEvaluator evaluator, String expression) {
      List<String> sequence = new ArrayList<>();
      evaluator.evaluate(expression, sequence);
      System.out.println("Evaluation sequence for :" + expression);

      for (String string : sequence) {
         System.out.println(string);
      }

      System.out.println();
   }
}
