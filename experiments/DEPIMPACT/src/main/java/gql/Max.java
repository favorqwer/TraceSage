package gql;

public class Max extends Clause {
   Collect collect;

   public Max(Collect collect) {
      this.collect = collect;
   }

   public Collect getCollect() {
      return this.collect;
   }

   public void setCollect(Collect collect) {
      this.collect = collect;
   }

   @Override
   public String toString() {
      return "max(" + this.collect.toString() + ")";
   }
}
