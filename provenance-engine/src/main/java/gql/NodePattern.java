package gql;

import java.util.List;

public class NodePattern extends Clause {
   public Variable variable;
   public NodeLabel label;
   public List<Property> propertyLst;

   public NodePattern(Variable variable, NodeLabel label) {
      this.variable = variable;
      this.label = label;
   }

   public NodePattern(Variable variable, NodeLabel label, List<Property> propertyLst) {
      this.variable = variable;
      this.label = label;
      this.propertyLst = propertyLst;
   }

   public Variable getVariable() {
      return this.variable;
   }

   public void setVariable(Variable variable) {
      this.variable = variable;
   }

   public NodeLabel getLabel() {
      return this.label;
   }

   public void setLabel(NodeLabel label) {
      this.label = label;
   }

   public List<Property> getPropertyLst() {
      return this.propertyLst;
   }

   public void setPropertyLst(List<Property> propertyLst) {
      this.propertyLst = propertyLst;
   }

   @Override
   public String toString() {
      if (!this.variable.toString().equals("") && !this.label.toString().equals("") && this.propertyLst != null) {
         String properties = "{";

         for (Property p : this.propertyLst) {
            properties = properties + p.getPropertyKeyname() + ":" + p.getExpression() + ",";
         }

         properties = properties.substring(0, properties.length() - 1) + "}";
         return "(" + this.variable.toString() + ":" + this.label.toString() + properties.toString() + ")";
      } else if (!this.variable.toString().equals("") && !this.label.toString().equals("")) {
         return "(" + this.variable.toString() + ":" + this.label.toString() + ")";
      } else {
         return !this.variable.toString().equals("") ? "(" + this.variable.toString() + ")" : "()";
      }
   }
}
