package gql;

public class PatternPart extends Clause {
   NodePattern nodePattern;
   PatternElementChain patternElementChain;

   public PatternPart(NodePattern nodePattern, PatternElementChain patternElementChain) {
      this.nodePattern = nodePattern;
      this.patternElementChain = patternElementChain;
   }

   public NodePattern getNodePattern() {
      return this.nodePattern;
   }

   public void setNodePattern(NodePattern nodePattern) {
      this.nodePattern = nodePattern;
   }

   public PatternElementChain getPatternElementChain() {
      return this.patternElementChain;
   }

   public void setPatternElementChain(PatternElementChain patternElementChain) {
      this.patternElementChain = patternElementChain;
   }

   @Override
   public String toString() {
      return this.nodePattern.toString() + this.patternElementChain.toString();
   }
}
