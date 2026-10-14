package gql;

public class Backward extends Clause {
   Variable variable;

   public Backward(Variable variable) {
      this.variable = variable;
   }

   public Variable getVariable() {
      return this.variable;
   }

   @Override
   public String toString() {
      return "backward (" + this.variable.toString() + ")";
   }
}
