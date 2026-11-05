package gql;

public class Return extends Clause {
   Variable variable;

   public Return(Variable variable) {
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
      return "RETURN " + this.variable.toString();
   }
}
