package gql;

public class Collect extends Clause {
   IdInColl idInColl;
   PropertyExpression propertyExpression;

   public Collect(IdInColl idInColl, PropertyExpression propertyExpression) {
      this.idInColl = idInColl;
      this.propertyExpression = propertyExpression;
   }

   public IdInColl getIdInColl() {
      return this.idInColl;
   }

   public void setIdInColl(IdInColl idInColl) {
      this.idInColl = idInColl;
   }

   public PropertyExpression getPropertyExpression() {
      return this.propertyExpression;
   }

   public void setPropertyExpression(PropertyExpression propertyExpression) {
      this.propertyExpression = propertyExpression;
   }

   @Override
   public String toString() {
      return "collect(" + this.idInColl.toString() + " | " + this.propertyExpression.toString() + ")";
   }
}
