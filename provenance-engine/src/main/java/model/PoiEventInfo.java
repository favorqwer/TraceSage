package model;

import java.math.BigDecimal;

public class PoiEventInfo {
   private final String sourceSignature;
   private final String sinkSignature;
   private final String eventType;
   private final BigDecimal startTime;
   private final BigDecimal endTime;

   public PoiEventInfo(String sourceSignature, String sinkSignature, String eventType, BigDecimal startTime, BigDecimal endTime) {
      this.sourceSignature = sourceSignature;
      this.sinkSignature = sinkSignature;
      this.eventType = eventType;
      this.startTime = startTime;
      this.endTime = endTime;
   }

   public String getSourceSignature() {
      return this.sourceSignature;
   }

   public String getSinkSignature() {
      return this.sinkSignature;
   }

   public String getEventType() {
      return this.eventType;
   }

   public BigDecimal getStartTime() {
      return this.startTime;
   }

   public BigDecimal getEndTime() {
      return this.endTime;
   }

   public boolean matches(EventEdge edge) {
      if (edge == null) {
         return false;
      } else if (!safeEquals(this.sourceSignature, edge.getSource().getSignature())) {
         return false;
      } else if (!safeEquals(this.sinkSignature, edge.getSink().getSignature())) {
         return false;
      } else if (this.eventType != null && !this.eventType.isEmpty() && !safeEquals(this.eventType, edge.getEvent())) {
         return false;
      } else if (this.startTime != null && edge.getStartTime() != null && this.startTime.compareTo(edge.getStartTime()) != 0) {
         return false;
      } else {
         return this.endTime == null || edge.getEndTime() == null || this.endTime.compareTo(edge.getEndTime()) == 0;
      }
   }

   public boolean matchesRelaxed(EventEdge edge) {
      if (edge == null) {
         return false;
      } else if (!safeEquals(this.sourceSignature, edge.getSource().getSignature())) {
         return false;
      } else if (!safeEquals(this.sinkSignature, edge.getSink().getSignature())) {
         return false;
      } else {
         return this.eventType == null || this.eventType.isEmpty() || safeEquals(this.eventType, edge.getEvent());
      }
   }

   private static boolean safeEquals(String left, String right) {
      return left == null ? right == null : left.equals(right);
   }
}
