package gql;

public class SET extends Clause {
   PropertyExpression propertyExpression;
   Reduce reduce;
   Projection projection;

   public SET(PropertyExpression propertyExpression, Reduce reduce) {
      this.propertyExpression = propertyExpression;
      this.reduce = reduce;
   }

   public SET(PropertyExpression propertyExpression, Projection projection) {
      this.propertyExpression = propertyExpression;
      this.projection = projection;
   }

   public PropertyExpression getPropertyExpression() {
      return this.propertyExpression;
   }

   public void setPropertyExpression(PropertyExpression propertyExpression) {
      this.propertyExpression = propertyExpression;
   }

   public Reduce getReduce() {
      return this.reduce;
   }

   public void setReduce(Reduce reduce) {
      this.reduce = reduce;
   }

   public Projection getProjection() {
      return this.projection;
   }

   public void setProjection(Projection projection) {
      this.projection = projection;
   }

   @Override
   public String toString() {
      if (this.reduce != null) {
         return "SET " + this.propertyExpression.toString() + "=" + this.reduce.toString();
      } else {
         return this.projection != null ? "SET " + this.propertyExpression.toString() + "=" + this.projection.toString() : "";
      }
   }
}
