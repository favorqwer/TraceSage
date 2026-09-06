package gql;

public class NumberLiteral extends Clause {
   String integer;

   public NumberLiteral(String integer) {
      this.integer = integer;
   }

   public String getInteger() {
      return this.integer;
   }

   public void setInteger(String integer) {
      this.integer = integer;
   }

   @Override
   public String toString() {
      return this.integer;
   }
}
