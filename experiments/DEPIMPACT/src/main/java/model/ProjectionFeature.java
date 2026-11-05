package model;

import java.util.List;

public class ProjectionFeature {
   String featureType;
   String featureExpr;
   List<String> variableTermLst;
   String denominator;

   public ProjectionFeature(String featureExpr) {
      this.featureExpr = featureExpr;
   }

   public String getFeatureType() {
      return this.featureType;
   }

   public void setFeatureType(String featureType) {
      this.featureType = featureType;
   }

   public String getFeatureExpr() {
      return this.featureExpr;
   }

   public List<String> getVariableTermLst() {
      return this.variableTermLst;
   }

   public void setVariableTermLst(List<String> termLst) {
      this.variableTermLst = termLst;
   }

   public String getDenominator() {
      return this.denominator;
   }

   public void setDenominator(String denominator) {
      this.denominator = denominator;
   }
}
