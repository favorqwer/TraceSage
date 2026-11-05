package gql;

public class Limit extends Clause {
   Expression expression;

   public Limit(Expression expression) {
      this.expression = expression;
   }

   public Expression getExpression() {
      return this.expression;
   }

   public void setExpression(Expression expression) {
      this.expression = expression;
   }

   @Override
   public String toString() {
      return "LIMIT " + this.expression.toString();
   }
}
