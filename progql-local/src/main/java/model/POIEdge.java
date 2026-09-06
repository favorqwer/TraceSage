package model;

import java.math.BigDecimal;

public class POIEdge {
   String poiEdgeName;
   BigDecimal poiStarttime;
   BigDecimal poiEndtime;
   double poiAmount;

   public POIEdge(String poiEdgeName) {
      this.poiEdgeName = poiEdgeName;
   }

   public POIEdge(String poiEdgeName, double poiAmount, BigDecimal poiStarttime, BigDecimal poiEndtime) {
      this.poiEdgeName = poiEdgeName;
      this.poiStarttime = poiStarttime;
      this.poiEndtime = poiEndtime;
      this.poiAmount = poiAmount;
   }

   public String getPoiEdgeName() {
      return this.poiEdgeName;
   }

   public void setPoiEdgeName(String poiEdgeName) {
      this.poiEdgeName = poiEdgeName;
   }

   public BigDecimal getPoiStarttime() {
      return this.poiStarttime;
   }

   public void setPoiStarttime(BigDecimal poiStarttime) {
      this.poiStarttime = poiStarttime;
   }

   public BigDecimal getPoiEndtime() {
      return this.poiEndtime;
   }

   public void setPoiEndtime(BigDecimal poiEndtime) {
      this.poiEndtime = poiEndtime;
   }

   public double getPoiAmount() {
      return this.poiAmount;
   }

   public void setPoiAmount(double poiAmount) {
      this.poiAmount = poiAmount;
   }
}
