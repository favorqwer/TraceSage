package model;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.math3.ml.clustering.Clusterable;

public class EventEdgeWrapper implements Clusterable {
   private double[] points;
   private EventEdge edge;
   private List<ProjectionFeature> projectionFeatureLst;

   public EventEdgeWrapper(EventEdge edge, List<ProjectionFeature> projectionFeatureLst) {
      this.edge = edge;
      this.projectionFeatureLst = projectionFeatureLst;
      this.points = this.createPointsArray(edge);
   }

   public EventEdgeWrapper(EventEdge edge, double[] ds) {
      this.edge = edge;
      this.points = ds;
   }

   public EventEdge getEventEdge() {
      return this.edge;
   }

   public double[] getPoint() {
      return this.points;
   }

   private double[] createPointsArray(EventEdge edge) {
      List<Double> pointsList = new ArrayList<>();
      ProjectionFeature amountFeature = this.projectionFeatureLst
         .stream()
         .filter(featurex -> "amount".equals(featurex.getFeatureType()))
         .findAny()
         .orElse(null);
      if (amountFeature != null && edge.amountWeight != null) {
         pointsList.add(edge.amountWeight);
      }

      ProjectionFeature timeFeature = this.projectionFeatureLst.stream().filter(featurex -> "time".equals(featurex.getFeatureType())).findAny().orElse(null);
      if (timeFeature != null && edge.timeWeight != null) {
         pointsList.add(edge.timeWeight);
      }

      ProjectionFeature structureFeature = this.projectionFeatureLst
         .stream()
         .filter(featurex -> "structure".equals(featurex.getFeatureType()))
         .findAny()
         .orElse(null);
      if (structureFeature != null && edge.structureWeight != null) {
         pointsList.add(edge.structureWeight);
      }

      ProjectionFeature feature = this.projectionFeatureLst.stream().filter(f -> f.getFeatureType() != null).findAny().orElse(null);
      if (feature == null) {
         if (this.projectionFeatureLst.size() == 3) {
            pointsList.add(edge.timeWeight);
            pointsList.add(edge.amountWeight);
            pointsList.add(edge.structureWeight);
         }

         if (this.projectionFeatureLst.size() == 2) {
            pointsList.add(edge.timeWeight);
            pointsList.add(edge.amountWeight);
         }

         if (this.projectionFeatureLst.size() == 1) {
            pointsList.add(edge.timeWeight);
         }
      }

      double[] points = new double[pointsList.size()];

      for (int i = 0; i < pointsList.size(); i++) {
         points[i] = pointsList.get(i);
      }

      return points;
   }
}
