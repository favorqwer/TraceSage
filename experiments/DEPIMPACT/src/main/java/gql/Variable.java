package gql;

public class Variable extends Clause {
   String symbolicName;

   public Variable(String symbolicName) {
      this.symbolicName = symbolicName;
   }

   public String getSymbolicName() {
      return this.symbolicName;
   }

   public void setSymbolicName(String symbolicName) {
      this.symbolicName = symbolicName;
   }

   @Override
   public String toString() {
      return this.symbolicName;
   }
}
