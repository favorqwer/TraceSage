package gql;

public class PropertyLookup extends Clause {
   String propertyName;

   public PropertyLookup(String propertyName) {
      this.propertyName = propertyName;
   }

   public String getPropertyName() {
      return this.propertyName;
   }

   public void setPropertyName(String property) {
      this.propertyName = property;
   }

   @Override
   public String toString() {
      return this.propertyName;
   }
}
