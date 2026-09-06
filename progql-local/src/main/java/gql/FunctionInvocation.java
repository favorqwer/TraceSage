package gql;

public class FunctionInvocation extends Clause {
   String functionName;
   Expression expression;

   public FunctionInvocation(String functionName, Expression expression) {
      this.functionName = functionName;
      this.expression = expression;
   }

   public String getFunctionName() {
      return this.functionName;
   }

   public void setFunctionName(String functionName) {
      this.functionName = functionName;
   }

   public Expression getExpression() {
      return this.expression;
   }

   public void setExpression(Expression expression) {
      this.expression = expression;
   }

   @Override
   public String toString() {
      return this.functionName + "(" + this.expression.toString() + ")";
   }
}
