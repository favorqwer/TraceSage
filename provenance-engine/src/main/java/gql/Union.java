package gql;

public class Union extends Clause {
   SingleQuery singlequery;
   WithQuery withquery;

   public Union(SingleQuery singlequery) {
      this.singlequery = singlequery;
   }

   public Union(WithQuery withquery) {
      this.withquery = withquery;
   }

   public SingleQuery getSinglequery() {
      return this.singlequery;
   }

   public void setSinglequery(SingleQuery singlequery) {
      this.singlequery = singlequery;
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
         return "UNION " + this.singlequery.toString();
      } else {
         return this.withquery != null ? "UNION " + this.withquery.toString() : null;
      }
   }
}
