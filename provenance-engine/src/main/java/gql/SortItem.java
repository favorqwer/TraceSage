package gql;

public class SortItem extends Clause {
   Expression expression;
   String ascordesc;

   public SortItem(Expression expression, String ascordesc) {
      this.expression = expression;
      this.ascordesc = ascordesc;
   }

   public Expression getExpression() {
      return this.expression;
   }

   public void setExpression(Expression expression) {
      this.expression = expression;
   }

   public String getAscordesc() {
      return this.ascordesc;
   }

   public void setAscordesc(String ascordesc) {
      this.ascordesc = ascordesc;
   }

   @Override
   public String toString() {
      return this.expression.toString() + " " + this.ascordesc;
   }
}
