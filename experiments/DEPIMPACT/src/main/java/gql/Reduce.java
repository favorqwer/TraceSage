package gql;

public class Reduce extends Clause {
   Variable variable;
   NumberLiteral numberliteral;
   IdInColl idincoll;
   Expression expression;

   public Reduce(Variable variable, NumberLiteral numberliteral, IdInColl idincoll, Expression expression) {
      this.variable = variable;
      this.numberliteral = numberliteral;
      this.idincoll = idincoll;
      this.expression = expression;
   }

   public Variable getVariable() {
      return this.variable;
   }

   public void setVariable(Variable variable) {
      this.variable = variable;
   }

   public NumberLiteral getNumberliteral() {
      return this.numberliteral;
   }

   public void setNumberliteral(NumberLiteral numberliteral) {
      this.numberliteral = numberliteral;
   }

   public IdInColl getIdincoll() {
      return this.idincoll;
   }

   public void setIdincoll(IdInColl idincoll) {
      this.idincoll = idincoll;
   }

   public Expression getExpression() {
      return this.expression;
   }

   public void setExpression(Expression expression) {
      this.expression = expression;
   }

   @Override
   public String toString() {
      return "REDUCE ("
         + this.variable.toString()
         + "="
         + this.numberliteral.toString()
         + " , "
         + this.idincoll.toString()
         + " | "
         + this.expression.toString()
         + ")";
   }
}
