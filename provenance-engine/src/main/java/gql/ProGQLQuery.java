package gql;

public class ProGQLQuery extends Clause {
   SingleQuery singlequery;
   String intersectOrUnion;
   WithQuery withquery;

   public ProGQLQuery(SingleQuery singlequery) {
      this.singlequery = singlequery;
   }

   public ProGQLQuery(SingleQuery singlequery, String intersectOrUnion, WithQuery withquery) {
      this.singlequery = singlequery;
      this.intersectOrUnion = intersectOrUnion;
      this.withquery = withquery;
   }

   public void setSinglequery(SingleQuery singlequery) {
      this.singlequery = singlequery;
   }

   public SingleQuery getSinglequery() {
      return this.singlequery;
   }

   public String getIntersectOrUnion() {
      return this.intersectOrUnion;
   }

   public void setIntersectOrUnion(String intersectOrUnion) {
      this.intersectOrUnion = intersectOrUnion;
   }

   public WithQuery getWithquery() {
      return this.withquery;
   }

   public void setWithquery(WithQuery withquery) {
      this.withquery = withquery;
   }

   @Override
   public String toString() {
      return this.withquery != null ? this.singlequery.toString() + " " + this.intersectOrUnion + " " + this.withquery.toString() : this.singlequery.toString();
   }
}
