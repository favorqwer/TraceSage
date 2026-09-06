package gql;

public class Pattern extends Clause {
   PatternPart patternPart;
   IdInColl idInColl;
   Expression expression;

   public Pattern(PatternPart patternPart) {
      this.patternPart = patternPart;
   }

   public Pattern(IdInColl idInColl) {
      this.idInColl = idInColl;
   }

   public Pattern(Expression expression) {
      this.expression = expression;
   }

   public PatternPart getPatternPart() {
      return this.patternPart;
   }

   public void setPatternPart(PatternPart patternPart) {
      this.patternPart = patternPart;
   }

   public IdInColl getIdInColl() {
      return this.idInColl;
   }

   public void setIdInColl(IdInColl idInColl) {
      this.idInColl = idInColl;
   }

   public Expression getExpression() {
      return this.expression;
   }

   public void setExpression(Expression expression) {
      this.expression = expression;
   }

   @Override
   public String toString() {
      if (this.patternPart != null) {
         return this.patternPart.toString();
      } else if (this.idInColl != null) {
         return this.idInColl.toString();
      } else {
         return this.expression != null ? this.expression.toString() : "";
      }
   }
}
