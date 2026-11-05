package gql;

public class PropertyExpression extends Clause {
   Atom atom;
   PropertyLookup propertyLookup;

   public PropertyExpression(Atom atom, PropertyLookup propertyLookup) {
      this.atom = atom;
      this.propertyLookup = propertyLookup;
   }

   public Atom getAtom() {
      return this.atom;
   }

   public void setAtom(Atom atom) {
      this.atom = atom;
   }

   public PropertyLookup getPropertyLookup() {
      return this.propertyLookup;
   }

   public void setPropertyLookup(PropertyLookup propertyLookup) {
      this.propertyLookup = propertyLookup;
   }

   @Override
   public String toString() {
      return this.atom.toString() + "." + this.propertyLookup.toString();
   }
}
