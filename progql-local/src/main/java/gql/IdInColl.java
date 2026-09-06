package gql;

public class IdInColl extends Clause {
   Variable var;
   Expression expression;

   public IdInColl(Variable var, Expression expression) {
      this.var = var;
      this.expression = expression;
   }

   public Variable getVar() {
      return this.var;
   }

   public void setVar(Variable var) {
      this.var = var;
   }

   public Expression getExpression() {
      return this.expression;
   }

   public void setExpression(Expression expression) {
      this.expression = expression;
   }

   @Override
   public String toString() {
      return this.var.toString() + " IN " + this.expression.toString();
   }
}
