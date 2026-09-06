package gql;

public class RelationshipDetail extends Clause {
   public Clause variable;
   public Clause type;
   public MapLiteral mapLiteral;

   public RelationshipDetail(Clause variable) {
      this.variable = variable;
   }

   public RelationshipDetail(Clause variable, Clause type, MapLiteral mapLiteral) {
      this.variable = variable;
      this.type = type;
      this.mapLiteral = mapLiteral;
   }

   public Clause getVariable() {
      return this.variable;
   }

   public void setVariable(Clause variable) {
      this.variable = variable;
   }

   public Clause getType() {
      return this.type;
   }

   public void setType(Clause type) {
      this.type = type;
   }

   public MapLiteral getMapLiteral() {
      return this.mapLiteral;
   }

   public void setMapLiteral(MapLiteral mapLiteral) {
      this.mapLiteral = mapLiteral;
   }

   @Override
   public String toString() {
      return this.type != null ? "[" + this.variable.toString() + this.type.toString() + this.mapLiteral + "]" : "[" + this.variable.toString() + "]";
   }
}
