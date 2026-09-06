package gql;

public class DFS extends Clause {
   Clause variable;
   Clause expression;
   Clause match;

   public DFS(Clause variable, Clause expression, Clause match) {
      this.variable = variable;
      this.expression = expression;
      this.match = match;
   }

   @Override
   public String toString() {
      return "DFS ( " + this.variable.toString() + " IN " + this.expression.toString() + " | " + this.match.toString() + ")";
   }
}
