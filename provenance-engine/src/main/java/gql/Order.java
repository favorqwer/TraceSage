package gql;

public class Order extends Clause {
   Clause sortitem;

   public Order(Clause sortitem) {
      this.sortitem = sortitem;
   }

   public Clause getSortitem() {
      return this.sortitem;
   }

   public void setSortitem(Clause sortitem) {
      this.sortitem = sortitem;
   }

   @Override
   public String toString() {
      return "ORDER BY " + this.sortitem.toString();
   }
}
