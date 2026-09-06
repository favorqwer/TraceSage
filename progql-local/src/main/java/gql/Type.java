package gql;

public class Type extends Clause {
   String relationshipType;

   public Type(String relationshipType) {
      this.relationshipType = relationshipType;
   }

   public String getRelationshipType() {
      return this.relationshipType;
   }

   public void setRelationshipType(String relationshipType) {
      this.relationshipType = relationshipType;
   }

   @Override
   public String toString() {
      return this.relationshipType;
   }
}
