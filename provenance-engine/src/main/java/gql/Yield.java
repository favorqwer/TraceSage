package gql;

public class Yield extends Clause {
   Variable variable;

   public Yield(Variable variable) {
      this.variable = variable;
   }

   public Variable getVariable() {
      return this.variable;
   }

   public void setVariable(Variable variable) {
      this.variable = variable;
   }

   @Override
   public String toString() {
      return "YIELD " + this.variable.toString();
   }
}
