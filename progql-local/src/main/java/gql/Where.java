package gql;

public class Where extends Clause {
   Expression expression;
   Order order;
   Limit limit;

   public Where(Expression expression) {
      this.expression = expression;
   }

   public Where(Expression expression, Order order) {
      this.expression = expression;
      this.order = order;
   }

   public Where(Expression expression, Limit limit) {
      this.expression = expression;
      this.limit = limit;
   }

   public Where(Expression expression, Order order, Limit limit) {
      this.expression = expression;
      this.order = order;
      this.limit = limit;
   }

   public Expression getExpression() {
      return this.expression;
   }

   public void setExpression(Expression expression) {
      this.expression = expression;
   }

   public Order getOrder() {
      return this.order;
   }

   public void setOrder(Order order) {
      this.order = order;
   }

   public Limit getLimit() {
      return this.limit;
   }

   public void setLimit(Limit limit) {
      this.limit = limit;
   }

   @Override
   public String toString() {
      if (this.order != null && this.limit != null) {
         return "WHERE " + this.expression.toString() + " " + this.order.toString() + " " + this.limit.toString();
      } else if (this.order != null && this.limit == null) {
         return "WHERE " + this.expression.toString() + " " + this.order.toString();
      } else {
         return this.order == null && this.limit != null
            ? "WHERE " + this.expression.toString() + " " + this.limit.toString()
            : "WHERE " + this.expression.toString();
      }
   }
}
