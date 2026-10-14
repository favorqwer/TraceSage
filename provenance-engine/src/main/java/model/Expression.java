package model;

public class Expression {
   String left;
   String operator;
   String right;

   public Expression(String left, String operator, String right) {
      this.left = left;
      this.operator = operator;
      this.right = right;
   }

   public String getLeft() {
      return this.left;
   }

   public String getOperator() {
      return this.operator;
   }

   public String getRight() {
      return this.right;
   }
}
