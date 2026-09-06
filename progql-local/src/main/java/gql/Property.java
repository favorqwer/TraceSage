package gql;

public class Property extends Clause {
   String propertyKeyname;
   String expression;

   public Property(String propertyKeyname, String expression) {
      this.propertyKeyname = propertyKeyname;
      this.expression = expression;
   }

   public String getPropertyKeyname() {
      return this.propertyKeyname;
   }

   public void setPropertyKeyname(String propertyKeyname) {
      this.propertyKeyname = propertyKeyname;
   }

   public String getExpression() {
      return this.expression;
   }

   public void setExpression(String expression) {
      this.expression = expression;
   }

   @Override
   public String toString() {
      return this.propertyKeyname + ":" + this.expression;
   }
}
