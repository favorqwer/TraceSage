package gql;

public class BFS extends Clause {
   Variable variable;
   Backward backward;
   Forward forward;
   Match match;

   public BFS(Variable variable, Backward backward, Match match) {
      this.variable = variable;
      this.backward = backward;
      this.match = match;
   }

   public BFS(Variable variable, Forward forward, Match match) {
      this.variable = variable;
      this.forward = forward;
      this.match = match;
   }

   public Variable getVariable() {
      return this.variable;
   }

   public void setVariable(Variable variable) {
      this.variable = variable;
   }

   public Backward getBackward() {
      return this.backward;
   }

   public void setBackward(Backward backward) {
      this.backward = backward;
   }

   public Forward getForward() {
      return this.forward;
   }

   public void setForward(Forward forward) {
      this.forward = forward;
   }

   public Match getMatch() {
      return this.match;
   }

   public void setMatch(Match match) {
      this.match = match;
   }

   @Override
   public String toString() {
      if (this.backward != null) {
         return "BFS (" + this.variable.toString() + " IN " + this.backward.toString() + " | " + this.match.toString() + ")";
      } else {
         return this.forward != null ? "BFS (" + this.variable.toString() + " IN " + this.forward.toString() + " | " + this.match.toString() + ")" : "";
      }
   }
}
