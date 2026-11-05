package gql;

public class Forward extends Clause {
   Variable variable;

   public Forward(Variable variable) {
      this.variable = variable;
   }

   public Variable getVariable() {
      return this.variable;
   }

   @Override
   public String toString() {
      return "forward (" + this.variable.toString() + ")";
   }
}
