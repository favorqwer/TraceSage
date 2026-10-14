package gql;

import java.util.List;

public class Expression extends Clause {
   String exprStr;
   List<PropertyExpression> propertyExpressionLst;
   TraversalExpression traversalExpression;
   Atom atom;

   public Expression(String exprStr) {
      this.exprStr = exprStr;
   }

   public String getExprStr() {
      return this.exprStr;
   }

   public void setExprStr(String exprStr) {
      this.exprStr = exprStr;
   }

   public List<PropertyExpression> getPropertyExpressionLst() {
      return this.propertyExpressionLst;
   }

   public void setPropertyExpressionLst(List<PropertyExpression> propertyExpressionLst) {
      this.propertyExpressionLst = propertyExpressionLst;
   }

   public TraversalExpression getTraversalExpression() {
      return this.traversalExpression;
   }

   public void setTraversalExpression(TraversalExpression traversalExpression) {
      this.traversalExpression = traversalExpression;
   }

   public Atom getAtom() {
      return this.atom;
   }

   public void setAtom(Atom atom) {
      this.atom = atom;
   }

   @Override
   public String toString() {
      return this.exprStr;
   }
}
