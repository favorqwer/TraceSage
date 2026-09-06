package gql;

public class RelationshipPattern extends Clause {
   public RelationshipDetail detail;
   public String arrow;

   public RelationshipPattern(RelationshipDetail detail, String arrow) {
      this.detail = detail;
      this.arrow = arrow;
   }

   public RelationshipDetail getDetail() {
      return this.detail;
   }

   public void setDetail(RelationshipDetail detail) {
      this.detail = detail;
   }

   @Override
   public String toString() {
      if (this.arrow.equals(">")) {
         return "-" + this.detail.toString() + "->";
      } else {
         return this.arrow.equals("<") ? "<-" + this.detail.toString() + "-" : "";
      }
   }
}
