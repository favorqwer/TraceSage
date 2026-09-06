package gql;

public class Atom extends Clause {
   Variable variable;
   FunctionInvocation functionInvocation;

   public Atom(Variable variable) {
      this.variable = variable;
   }

   public Atom(FunctionInvocation functionInvocation) {
      this.functionInvocation = functionInvocation;
   }

   public Variable getVariable() {
      return this.variable;
   }

   public void setVariable(Variable variable) {
      this.variable = variable;
   }

   public FunctionInvocation getFunctionInvocation() {
      return this.functionInvocation;
   }

   public void setFunctionInvocation(FunctionInvocation functionInvocation) {
      this.functionInvocation = functionInvocation;
   }

   @Override
   public String toString() {
      if (this.variable != null) {
         return this.variable.toString();
      } else {
         return this.functionInvocation != null ? this.functionInvocation.toString() : "";
      }
   }
}
