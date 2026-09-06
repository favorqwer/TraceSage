package gql;

public class PatternElementChain extends Clause {
   public RelationshipPattern relationshipPattern;
   public NodePattern nodePattern;

   public PatternElementChain(RelationshipPattern relationshipPattern, NodePattern nodePattern) {
      this.relationshipPattern = relationshipPattern;
      this.nodePattern = nodePattern;
   }

   public RelationshipPattern getRelationshipPattern() {
      return this.relationshipPattern;
   }

   public void setRelationshipPattern(RelationshipPattern relationshipPattern) {
      this.relationshipPattern = relationshipPattern;
   }

   public NodePattern getNodePattern() {
      return this.nodePattern;
   }

   public void setNodePattern(NodePattern nodePattern) {
      this.nodePattern = nodePattern;
   }

   @Override
   public String toString() {
      return this.relationshipPattern.toString() + this.nodePattern.toString();
   }
}
