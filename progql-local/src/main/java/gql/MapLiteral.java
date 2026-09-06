package gql;

public class MapLiteral extends Clause {
   String propertyKeyname;
   String literal;

   public MapLiteral(String propertyKeyname, String literal) {
      this.propertyKeyname = propertyKeyname;
      this.literal = literal;
   }

   public String getPropertyKeyname() {
      return this.propertyKeyname;
   }

   public void setPropertyKeyname(String propertyKeyname) {
      this.propertyKeyname = propertyKeyname;
   }

   public String getLiteral() {
      return this.literal;
   }

   public void setLiteral(String literal) {
      this.literal = literal;
   }

   @Override
   public String toString() {
      return "{" + this.propertyKeyname + ":" + this.literal + "}";
   }
}
