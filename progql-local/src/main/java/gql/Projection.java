package gql;

import java.util.List;

public class Projection extends Clause {
   List<Expression> expressionLst;

   public Projection(List<Expression> expressionLst) {
      this.expressionLst = expressionLst;
   }

   public List<Expression> getExpressionLst() {
      return this.expressionLst;
   }

   public void setExpressionLst(List<Expression> expressionLst) {
      this.expressionLst = expressionLst;
   }

   @Override
   public String toString() {
      String s = "";

      for (Expression expression : this.expressionLst) {
         s = s + expression.toString() + ", ";
      }

      s = s.substring(0, s.length() - 2);
      return "PROJECTION (" + s + ")";
   }
}
