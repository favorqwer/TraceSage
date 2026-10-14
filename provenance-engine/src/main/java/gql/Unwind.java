package gql;

public class Unwind extends Clause {
   Expression expression;
   Variable variable;

   public Unwind(Expression expression, Variable variable) {
      this.expression = expression;
      this.variable = variable;
   }

   public Expression getExpression() {
      return this.expression;
   }

   public void setExpression(Expression expression) {
      this.expression = expression;
   }

   public Variable getVariable() {
      return this.variable;
   }

   public void setVariable(Variable variable) {
      this.variable = variable;
   }

   @Override
   public String toString() {
      return "UNWIND " + this.expression.toString() + " AS " + this.variable.toString();
   }
}
