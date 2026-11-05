package gql;

public class Intersect extends Clause {
   SingleQuery singlequery;
   WithQuery withquery;

   public Intersect(SingleQuery singlequery) {
      this.singlequery = singlequery;
   }

   public Intersect(WithQuery withquery) {
      this.withquery = withquery;
   }

   public void setSinglequery(SingleQuery singlequery) {
      this.singlequery = singlequery;
   }

   public SingleQuery getSinglequery() {
      return this.singlequery;
   }

   public WithQuery getWithquery() {
      return this.withquery;
   }

   public void setWithquery(WithQuery withquery) {
      this.withquery = withquery;
   }

   @Override
   public String toString() {
      if (this.singlequery != null) {
         return "INTERSECT " + this.singlequery.toString();
      } else {
         return this.withquery != null ? "INTERSECT " + this.withquery.toString() : null;
      }
   }
}
