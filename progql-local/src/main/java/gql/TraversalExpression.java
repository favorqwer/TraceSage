package gql;

public class TraversalExpression extends Clause {
   Max max;
   Min min;

   public TraversalExpression() {
   }

   public TraversalExpression(Max max) {
      this.max = max;
   }

   public TraversalExpression(Min min) {
      this.min = min;
   }

   public Max getMax() {
      return this.max;
   }

   public void setMax(Max max) {
      this.max = max;
   }

   public Min getMin() {
      return this.min;
   }

   public void setMin(Min min) {
      this.min = min;
   }

   @Override
   public String toString() {
      if (this.max != null) {
         return this.max.toString();
      } else {
         return this.min != null ? this.min.toString() : "";
      }
   }
}
