package util;

import com.fathzer.soft.javaluator.DoubleEvaluator;
import com.fathzer.soft.javaluator.StaticVariableSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import model.Edge;
import model.EntityNode;
import model.EventEdge;
import model.EventEdgeWrapper;
import model.POIEdge;
import model.ProjectionFeature;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.math3.linear.Array2DRowRealMatrix;
import org.apache.commons.math3.linear.ArrayRealVector;
import org.apache.commons.math3.linear.DecompositionSolver;
import org.apache.commons.math3.linear.RealMatrix;
import org.apache.commons.math3.linear.RealVector;
import org.apache.commons.math3.linear.SingularValueDecomposition;
import org.apache.commons.math3.ml.clustering.Cluster;
import org.apache.commons.math3.ml.clustering.DBSCANClusterer;
import org.apache.commons.math3.ml.clustering.KMeansPlusPlusClusterer;
import org.apache.commons.math3.ml.clustering.MultiKMeansPlusPlusClusterer;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.jgrapht.graph.DirectedPseudograph;
import org.junit.Assert;

public class GQLBackwardPropagate {
   DirectedPseudograph<EntityNode, EventEdge> graph;
   Map<Long, Double> weights = new HashMap<>();
   Map<Long, Double> timeWeights = new HashMap<>();
   Map<Long, Double> amountWeights = new HashMap<>();
   Map<Long, Double> structureWeights = new HashMap<>();
   Edge myEdge;
   POIEdge poiEdge;
   Set<String> seedSources;
   List<ProjectionFeature> projectionFeatureLst;
   double dumpingFactor;

   public GQLBackwardPropagate(DirectedPseudograph<EntityNode, EventEdge> graph) {
      this.graph = graph;
      this.dumpingFactor = 0.85;
   }

   public Edge getMyEdge() {
      return this.myEdge;
   }

   public void setMyEdge(Edge myEdge) {
      this.myEdge = myEdge;
   }

   public POIEdge getPoiEdge() {
      return this.poiEdge;
   }

   public void setPoiEdge(POIEdge poiEdge) {
      this.poiEdge = poiEdge;
   }

   public Set<String> getSeedSources() {
      return this.seedSources;
   }

   public void setSeedSources(Set<String> seedSources) {
      this.seedSources = seedSources;
   }

   public List<ProjectionFeature> getProjectionFeatureLst() {
      return this.projectionFeatureLst;
   }

   public void setProjectionFeatureLst(List<ProjectionFeature> projectionFeatureLst) {
      this.projectionFeatureLst = projectionFeatureLst;
   }

   private Double getFeatureWeight(EventEdge edge, ProjectionFeature feature) {
      Double result = null;
      DoubleEvaluator eval = new DoubleEvaluator();
      StaticVariableSet<Double> variables = new StaticVariableSet();
      List<String> variableTermLst = feature.getVariableTermLst();
      if (feature.getFeatureType().equals("amount")) {
         for (String variableTerm : variableTermLst) {
            if (variableTerm.substring(0, variableTerm.indexOf(".")).equalsIgnoreCase(this.myEdge.getEdgeName())) {
               variables.set(variableTerm, (double)edge.getSize());
            }

            if (variableTerm.substring(0, variableTerm.indexOf(".")).equalsIgnoreCase(this.poiEdge.getPoiEdgeName())) {
               variables.set(variableTerm, this.poiEdge.getPoiAmount());
            }
         }

         result = (Double)eval.evaluate(feature.getFeatureExpr(), variables);
      }

      if (feature.getFeatureType().equals("time")) {
         for (String variableTerm : variableTermLst) {
            if (variableTerm.substring(0, variableTerm.indexOf(".")).equalsIgnoreCase(this.myEdge.getEdgeName())) {
               if (variableTerm.substring(variableTerm.indexOf(".") + 1).equalsIgnoreCase("endtime")) {
                  variables.set(variableTerm, edge.getEndTime().doubleValue());
               }

               if (variableTerm.substring(variableTerm.indexOf(".") + 1).equalsIgnoreCase("starttime")) {
                  variables.set(variableTerm, edge.getStartTime().doubleValue());
               }
            }

            if (variableTerm.substring(0, variableTerm.indexOf(".")).equalsIgnoreCase(this.poiEdge.getPoiEdgeName())) {
               if (variableTerm.substring(variableTerm.indexOf(".") + 1).equalsIgnoreCase("endtime")) {
                  variables.set(variableTerm, this.poiEdge.getPoiEndtime().doubleValue());
               }

               if (variableTerm.substring(variableTerm.indexOf(".") + 1).equalsIgnoreCase("starttime")) {
                  variables.set(variableTerm, this.poiEdge.getPoiStarttime().doubleValue());
               }
            }
         }

         String denominator = feature.getDenominator();
         if (denominator != null) {
            Double denominatorResult = (Double)eval.evaluate(denominator, variables);
            if (denominatorResult == 0.0) {
               result = (Double)eval.evaluate(feature.getFeatureExpr().replace(denominator, "0.0000000001"), variables);
            } else {
               result = (Double)eval.evaluate(feature.getFeatureExpr(), variables);
            }
         } else {
            result = (Double)eval.evaluate(feature.getFeatureExpr(), variables);
         }

         if (result != null && (result.isNaN() || result.isInfinite())) {
            // A zero end-time difference against the POI edge drives the expression
            // to 1/0; fall back to the pseudo-minimum difference handling of
            // getTimeWeight so the feature stays finite for clustering.
            result = getTimeWeight(edge);
         }
      }

      if (feature.getFeatureType().equals("structure")) {
         EntityNode sink = edge.getSink();
         int inDegree = this.graph.inDegreeOf(sink);
         int outDegree = this.graph.outDegreeOf(sink);
         if (this.seedSources.contains(sink.getSignature())) {
            return (double)this.graph.edgeSet().size() * 1.0;
         }

         String[] strArr = feature.getFeatureExpr().split("/");
         if (strArr[0].contains("out") && strArr[1].contains("in")) {
            result = (double)outDegree / ((double)inDegree * 1.0);
         }

         if (strArr[0].contains("out") && strArr[1].contains("out") || strArr[0].contains("in") && strArr[1].contains("in")) {
            result = 1.0;
         }

         if (strArr[0].contains("in") && strArr[1].contains("out")) {
            result = (double)inDegree / ((double)outDegree * 1.0);
         }
      }

      return result;
   }

   private void preprocessWeights(Map<Long, Double> weights, boolean normalizeByOutEdges) {
      if (normalizeByOutEdges) {
         this.normalizeWeightsByOutEdges(weights);
      } else {
         this.standardizeWeights(weights);
      }
   }

   private void normalizeWeightsByOutEdges(Map<Long, Double> weights) {
      for (EntityNode n : this.graph.vertexSet()) {
         Set<EventEdge> outgoing = this.graph.outgoingEdgesOf(n);
         double weightTotal = 0.0;

         for (EventEdge out : outgoing) {
            weightTotal += weights.get(out.id);
         }

         if (weightTotal > Double.MIN_VALUE) {
            for (EventEdge out : outgoing) {
               double normalizedWeight = weights.get(out.id) / weightTotal;
               weights.put(out.id, normalizedWeight);
            }
         }
      }
   }

   private void normalizeWeightsByInEdges(Map<Long, Double> weights) {
      for (EntityNode n : this.graph.vertexSet()) {
         Set<EventEdge> incoming = this.graph.incomingEdgesOf(n);
         double weightTotal = 0.0;

         for (EventEdge in : incoming) {
            weightTotal += weights.get(in.id);
         }

         if (weightTotal > Double.MIN_VALUE) {
            for (EventEdge in : incoming) {
               double normalizedWeight = weights.get(in.id) / weightTotal;
               weights.put(in.id, normalizedWeight);
            }
         }
      }
   }

   private void standardizeWeights(Map<Long, Double> weights) {
      DescriptiveStatistics stats = new DescriptiveStatistics();

      for (Long edgeID : weights.keySet()) {
         stats.addValue(weights.get(edgeID));
      }

      double mean = stats.getMean();
      double std = stats.getStandardDeviation();

      for (long edgeID : weights.keySet()) {
         double standardizedWeight = (weights.get(edgeID) - mean) / std;
         weights.put(edgeID, standardizedWeight);
      }
   }

   private double getTimeWeight(EventEdge edge) {
      double res;
      if (edge.getEndTime().equals(this.poiEdge.getPoiEndtime())) {
         double pseudoMinDiff = 1.0E-10;
         res = Math.log(1.0 + 1.0 / Math.abs(pseudoMinDiff));
      } else {
         res = Math.log(1.0 + 1.0 / Math.abs(edge.getEndTime().doubleValue() - this.poiEdge.getPoiEndtime().doubleValue()));
      }

      return res;
   }

   private double getAmountWeight(EventEdge edge) {
      return 1.0 / (Math.abs((double)edge.getSize() - this.poiEdge.getPoiAmount()) + 1.0E-4);
   }

   private double getStructureWeight(EventEdge e) {
      EntityNode sink = e.getSink();
      int inDegree = this.graph.inDegreeOf(sink);
      int outDegree = this.graph.outDegreeOf(sink);
      double res;
      if (this.seedSources.contains(sink.getSignature())) {
         res = (double)this.graph.edgeSet().size() * 1.0;
      } else {
         res = (double)outDegree / ((double)inDegree * 1.0);
      }

      return res;
   }

   public void calculateWeights_ML_ClusterAll(boolean normalizeByOutEdges) {
      long start = System.currentTimeMillis();
      Set<EntityNode> vertexSet = this.graph.vertexSet();
      DoubleEvaluator eval = new DoubleEvaluator();

      for (EntityNode n : vertexSet) {
         for (EventEdge inEdge : this.graph.incomingEdgesOf(n)) {
            ProjectionFeature amountFeature = this.projectionFeatureLst
               .stream()
               .filter(feature -> "amount".equals(feature.getFeatureType()))
               .findAny()
               .orElse(null);
            if (amountFeature != null) {
               this.amountWeights.put(inEdge.id, this.getFeatureWeight(inEdge, amountFeature));
            }

            ProjectionFeature timeFeature = this.projectionFeatureLst
               .stream()
               .filter(feature -> "time".equals(feature.getFeatureType()))
               .findAny()
               .orElse(null);
            if (timeFeature != null) {
               this.timeWeights.put(inEdge.id, this.getFeatureWeight(inEdge, timeFeature));
            }

            ProjectionFeature structureFeature = this.projectionFeatureLst
               .stream()
               .filter(feature -> "structure".equals(feature.getFeatureType()))
               .findAny()
               .orElse(null);
            if (structureFeature != null) {
               this.structureWeights.put(inEdge.id, this.getFeatureWeight(inEdge, structureFeature));
            }

            ProjectionFeature feature = this.projectionFeatureLst.stream().filter(f -> f.getFeatureType() != null).findAny().orElse(null);
            if (feature == null) {
               if (this.projectionFeatureLst.size() == 3) {
                  this.timeWeights.put(inEdge.id, (Double)eval.evaluate(this.projectionFeatureLst.get(0).getFeatureExpr()));
                  this.amountWeights.put(inEdge.id, (Double)eval.evaluate(this.projectionFeatureLst.get(1).getFeatureExpr()));
                  this.structureWeights.put(inEdge.id, (Double)eval.evaluate(this.projectionFeatureLst.get(2).getFeatureExpr()));
               }

               if (this.projectionFeatureLst.size() == 2) {
                  this.timeWeights.put(inEdge.id, (Double)eval.evaluate(this.projectionFeatureLst.get(0).getFeatureExpr()));
                  this.amountWeights.put(inEdge.id, (Double)eval.evaluate(this.projectionFeatureLst.get(1).getFeatureExpr()));
               }

               if (this.projectionFeatureLst.size() == 1) {
                  this.timeWeights.put(inEdge.id, (Double)eval.evaluate(this.projectionFeatureLst.get(0).getFeatureExpr()));
               }
            }
         }
      }

      if (this.timeWeights.size() > 0) {
         this.preprocessWeights(this.timeWeights, normalizeByOutEdges);
      }

      if (this.amountWeights.size() > 0) {
         this.preprocessWeights(this.amountWeights, normalizeByOutEdges);
      }

      if (this.structureWeights.size() > 0) {
         this.preprocessWeights(this.structureWeights, normalizeByOutEdges);

         for (EntityNode n : vertexSet) {
            for (EventEdge inEdge : this.graph.incomingEdgesOf(n)) {
               if (this.seedSources.contains(inEdge.getSink().getSignature())) {
                  this.structureWeights.put(inEdge.id, 1.0);
               }
            }
         }
      }

      for (EntityNode n : vertexSet) {
         for (EventEdge inEdgex : this.graph.incomingEdgesOf(n)) {
            if (this.amountWeights.get(inEdgex.id) != null) {
               inEdgex.amountWeight = this.amountWeights.get(inEdgex.id);
            }

            if (this.timeWeights.get(inEdgex.id) != null) {
               inEdgex.timeWeight = this.timeWeights.get(inEdgex.id);
            }

            if (this.structureWeights.get(inEdgex.id) != null) {
               inEdgex.structureWeight = this.structureWeights.get(inEdgex.id);
            }
         }
      }

      List<EventEdge> allEdges = new ArrayList<>(this.graph.edgeSet());
      List<Double> finalWeights = null;
      if (this.projectionFeatureLst.size() == 1) {
         finalWeights = this.computeFinalWeights_Individual(allEdges, this.projectionFeatureLst.get(0).getFeatureType());
      } else {
         finalWeights = this.computeFinalWeights(allEdges);
      }

      for (int i = 0; i < allEdges.size(); i++) {
         allEdges.get(i).weight = finalWeights.get(i);
      }

      for (EntityNode n : vertexSet) {
         Set<EventEdge> outs = this.graph.outgoingEdgesOf(n);
         double weightTotalForOutEdges = 0.0;

         for (EventEdge out : outs) {
            weightTotalForOutEdges += out.weight;
         }

         if (!(weightTotalForOutEdges < 1.0E-8)) {
            for (EventEdge outEdge : outs) {
               outEdge.weight = outEdge.weight / weightTotalForOutEdges * 0.99;
               this.weights.put(outEdge.id, outEdge.weight);
            }
         } else {
            for (EventEdge outEdge : outs) {
               this.weights.put(outEdge.id, 0.0);
            }
         }
      }

      long end = System.currentTimeMillis();
      double timeCost = (double)(end - start) * 1.0 / 1000.0;
   }

   private List<Double> computeFinalWeights(List<EventEdge> allEdges) {
      int dim = this.projectionFeatureLst.size();
      if (dim == 3) {
         List<Cluster<EventEdgeWrapper>> clusterResults = this.clusterEdges(allEdges, "multiKmeansPlusPlus");
         List<Double> finalWeights = this.dimReduction(allEdges, clusterResults);
         this.scaleRange(finalWeights);
         return finalWeights;
      } else {
         List<Double[]> weights2DArrayAll = new ArrayList<>();

         for (EventEdge edge : allEdges) {
            List<Double> vec = new ArrayList<>();

            for (ProjectionFeature pf : this.projectionFeatureLst) {
               String weightsProjectedAll;
               switch ((weightsProjectedAll = pf.getFeatureType()).hashCode()) {
                  case -1413853096:
                     if (weightsProjectedAll.equals("amount")) {
                        vec.add(edge.amountWeight != null ? edge.amountWeight : 0.0);
                     }
                     break;
                  case 3560141:
                     if (weightsProjectedAll.equals("time")) {
                        vec.add(edge.timeWeight != null ? edge.timeWeight : 0.0);
                     }
                     break;
                  case 144518515:
                     if (weightsProjectedAll.equals("structure")) {
                        vec.add(edge.structureWeight != null ? edge.structureWeight : 0.0);
                     }
               }
            }

            weights2DArrayAll.add(vec.toArray(new Double[0]));
         }

         List<Double> finalWeights = new ArrayList<>();
         if (dim == 1) {
            for (Double[] vec : weights2DArrayAll) {
               finalWeights.add(vec[0]);
            }

            this.scaleRange(finalWeights);
         } else if (dim == 2) {
            List<Cluster<EventEdgeWrapper>> clusterResults = this.clusterEdges(allEdges, "multiKmeansPlusPlus");
            double[][] weightsMatrixAll = DoubleTodoubleArray(weights2DArrayAll.toArray(new Double[0][]));
            RealMatrix weightsMatrix = new Array2DRowRealMatrix(weightsMatrixAll);
            RealVector projectionVector = this.computeProjectionVectorForFeatures(allEdges, weightsMatrix, clusterResults);
            RealVector weightsProjectedAll = weightsMatrix.operate(projectionVector);

            double[] var14;
            for (double w : var14 = weightsProjectedAll.toArray()) {
               finalWeights.add(w);
            }

            this.scaleRange(finalWeights);
         }

         return finalWeights;
      }
   }

   private RealVector computeProjectionVectorForFeatures(List<EventEdge> allEdges, RealMatrix weightsMatrix, List<Cluster<EventEdgeWrapper>> clusterResults) {
      int dim = weightsMatrix.getColumnDimension();
      Map<EventEdge, Integer> edgeToIndex = new HashMap<>();

      for (int i = 0; i < allEdges.size(); i++) {
         edgeToIndex.put(allEdges.get(i), i);
      }

      List<Integer> cluster1 = new ArrayList<>();
      List<Integer> cluster2 = new ArrayList<>();

      for (int i = 0; i < clusterResults.size(); i++) {
         for (EventEdgeWrapper w : clusterResults.get(i).getPoints()) {
            EventEdge e = w.getEventEdge();
            Integer idx = edgeToIndex.get(e);
            if (idx != null) {
               if (i == 0) {
                  cluster1.add(idx);
               } else {
                  cluster2.add(idx);
               }
            }
         }
      }

      RealVector mean1 = new ArrayRealVector(dim);

      for (int idx : cluster1) {
         mean1 = mean1.add(weightsMatrix.getRowVector(idx));
      }

      if (!cluster1.isEmpty()) {
         mean1.mapDivideToSelf((double)cluster1.size());
      }

      RealVector mean2 = new ArrayRealVector(dim);

      for (int idx : cluster2) {
         mean2 = mean2.add(weightsMatrix.getRowVector(idx));
      }

      if (!cluster2.isEmpty()) {
         mean2.mapDivideToSelf((double)cluster2.size());
      }

      RealMatrix Sw = new Array2DRowRealMatrix(dim, dim);

      for (int idx : cluster1) {
         RealVector diff = weightsMatrix.getRowVector(idx).subtract(mean1);
         Sw = Sw.add(diff.outerProduct(diff));
      }

      for (int idx : cluster2) {
         RealVector diff = weightsMatrix.getRowVector(idx).subtract(mean2);
         Sw = Sw.add(diff.outerProduct(diff));
      }

      RealVector meanDiff = mean1.subtract(mean2);
      DecompositionSolver solver = new SingularValueDecomposition(Sw).getSolver();
      RealVector projection = solver.solve(meanDiff);
      if (projection.getNorm() > 1.0E-10) {
         projection = projection.mapDivide(projection.getNorm());
      }

      return projection;
   }

   private List<Double> computeFinalWeights_local(List<EventEdge> allEdges) {
      List<Double> finalWeights = new ArrayList<>();

      for (int i = 0; i < allEdges.size(); i++) {
         finalWeights.add(0.0);
      }

      for (EntityNode n : this.graph.vertexSet()) {
         List<EventEdge> outEdges = new ArrayList<>(this.graph.outgoingEdgesOf(n));
         if (outEdges.size() == 0) {
         } else if (outEdges.size() == 1) {
            finalWeights.set(allEdges.indexOf(outEdges.get(0)), 1.0);
         } else {
            List<Cluster<EventEdgeWrapper>> clusterResults = this.clusterEdges(outEdges, "multiKmeansPlusPlus");
            if (clusterResults.size() == 1) {
               double amount = 0.0;

               for (EventEdge e : outEdges) {
                  amount += (double)e.getSize();
               }

               double wTotal = 0.0;
               if (amount < 1.0E-8) {
                  for (EventEdge outEdge : outEdges) {
                     finalWeights.set(allEdges.indexOf(outEdge), 0.5 * outEdge.timeWeight + 0.5 * outEdge.structureWeight);
                  }
               } else {
                  for (EventEdge outEdge : outEdges) {
                     finalWeights.set(allEdges.indexOf(outEdge), 0.3333 * outEdge.timeWeight + 0.3333 * outEdge.structureWeight + 0.3334 * outEdge.amountWeight);
                  }
               }
            } else {
               List<Double> weightsForOutEdges = this.dimReduction(outEdges, clusterResults);
               this.scaleRange(weightsForOutEdges);
               double weightTotalForOutEdges = 0.0;

               for (double weight : weightsForOutEdges) {
                  weightTotalForOutEdges += weight;
               }

               List<Double> weightsNormalizedByOutEdges = new ArrayList<>();
               if (weightTotalForOutEdges > 1.0E-8) {
                  for (double weight : weightsForOutEdges) {
                     weightsNormalizedByOutEdges.add(weight / (1.0 * weightTotalForOutEdges));
                  }
               }

               for (EventEdge edge : outEdges) {
                  finalWeights.set(allEdges.indexOf(edge), weightsForOutEdges.get(outEdges.indexOf(edge)));
               }
            }
         }
      }

      return finalWeights;
   }

   private void scaleRange(List<Double> numbers) {
      DescriptiveStatistics stats = new DescriptiveStatistics();

      for (double n : numbers) {
         stats.addValue(n);
      }

      double min = stats.getMin();
      double max = stats.getMax();
      double secondMin = max;

      for (double n : numbers) {
         if (n != min && n < secondMin) {
            secondMin = n;
         }
      }

      double offset = (secondMin - min) / 100.0;

      for (int i = 0; i < numbers.size(); i++) {
         numbers.set(i, (numbers.get(i) - min + offset) / (max - min));
      }
   }

   private List<Double> dimReduction(List<EventEdge> allEdges, List<Cluster<EventEdgeWrapper>> clusterResults) {
      assert clusterResults.size() == 2;

      Double[][] weights2DArrayAll = new Double[allEdges.size()][3];
      Double[][] weights2DArrayG0 = new Double[clusterResults.get(0).getPoints().size()][3];
      Double[][] weights2DArrayG1 = new Double[clusterResults.get(1).getPoints().size()][3];
      boolean seedEdgeInG0 = false;
      boolean seedEdgeInG1 = false;

      for (int i = 0; i < allEdges.size(); i++) {
         EventEdge edge = allEdges.get(i);
         weights2DArrayAll[i] = new Double[0];
         weights2DArrayAll[i] = addX(weights2DArrayAll[i], edge.amountWeight != null ? edge.amountWeight : 0.0);
         weights2DArrayAll[i] = addX(weights2DArrayAll[i], edge.timeWeight != null ? edge.timeWeight : 0.0);
         weights2DArrayAll[i] = addX(weights2DArrayAll[i], edge.structureWeight != null ? edge.structureWeight : 0.0);
      }

      for (int i = 0; i < clusterResults.get(0).getPoints().size(); i++) {
         EventEdge edge = ((EventEdgeWrapper)clusterResults.get(0).getPoints().get(i)).getEventEdge();
         weights2DArrayG0[i] = new Double[0];
         weights2DArrayG0[i] = addX(weights2DArrayG0[i], edge.amountWeight != null ? edge.amountWeight : 0.0);
         weights2DArrayG0[i] = addX(weights2DArrayG0[i], edge.timeWeight != null ? edge.timeWeight : 0.0);
         weights2DArrayG0[i] = addX(weights2DArrayG0[i], edge.structureWeight != null ? edge.structureWeight : 0.0);
         if (this.seedSources.contains(edge.getSource().getSignature())) {
            seedEdgeInG0 = true;
         }
      }

      for (int ix = 0; ix < clusterResults.get(1).getPoints().size(); ix++) {
         EventEdge edge = ((EventEdgeWrapper)clusterResults.get(1).getPoints().get(ix)).getEventEdge();
         weights2DArrayG1[ix] = new Double[0];
         weights2DArrayG1[ix] = addX(weights2DArrayG1[ix], edge.amountWeight != null ? edge.amountWeight : 0.0);
         weights2DArrayG1[ix] = addX(weights2DArrayG1[ix], edge.timeWeight != null ? edge.timeWeight : 0.0);
         weights2DArrayG1[ix] = addX(weights2DArrayG1[ix], edge.structureWeight != null ? edge.structureWeight : 0.0);
         if (this.seedSources.contains(edge.getSource().getSignature())) {
            seedEdgeInG1 = true;
         }
      }

      RealMatrix weightsMatrixAll = new Array2DRowRealMatrix(DoubleTodoubleArray(weights2DArrayAll));
      RealMatrix weightsMatrixG0 = new Array2DRowRealMatrix(DoubleTodoubleArray(weights2DArrayG0));
      RealMatrix weightsMatrixG1 = new Array2DRowRealMatrix(DoubleTodoubleArray(weights2DArrayG1));
      RealVector projectionVector = this.computeProjectionVector(weightsMatrixG0, weightsMatrixG1);
      this.adjustProjectionVectorDirection(projectionVector, weightsMatrixG0, weightsMatrixG1, seedEdgeInG0, seedEdgeInG1);
      RealVector weightsProjectedAll = weightsMatrixAll.operate(projectionVector);
      double[] finalWeights = weightsProjectedAll.toArray();
      return new ArrayList<>(Arrays.asList(ArrayUtils.toObject(finalWeights)));
   }

   public static double[][] DoubleTodoubleArray(Double[][] array) {
      double[][] doubles = new double[array.length][];

      for (int i = 0; i < array.length; i++) {
         doubles[i] = new double[array[i].length];

         for (int j = 0; j < array[i].length; j++) {
            doubles[i][j] = array[i][j];
         }
      }

      return doubles;
   }

   private void adjustProjectionVectorDirection(
      RealVector projectionVector, RealMatrix matrixG0, RealMatrix matrixG1, boolean seedEdgeInG0, boolean seedEdgeInG1
   ) {
      if (projectionVector.getEntry(0) <= 0.0 && projectionVector.getEntry(1) <= 0.0 && projectionVector.getEntry(2) <= 0.0) {
         projectionVector.mapMultiplyToSelf(-1.0);
      }

      if (!(projectionVector.getEntry(0) >= 0.0) || !(projectionVector.getEntry(1) >= 0.0) || !(projectionVector.getEntry(2) >= 0.0)) {
         RealVector mu0 = new ArrayRealVector(new double[]{0.0, 0.0, 0.0});

         for (int i = 0; i < matrixG0.getRowDimension(); i++) {
            mu0 = mu0.add(matrixG0.getRowVector(i));
         }

         mu0.mapDivideToSelf((double)matrixG0.getRowDimension());
         RealVector mu1 = new ArrayRealVector(new double[]{0.0, 0.0, 0.0});

         for (int i = 0; i < matrixG1.getRowDimension(); i++) {
            mu1 = mu1.add(matrixG1.getRowVector(i));
         }

         mu1.mapDivideToSelf((double)matrixG1.getRowDimension());
         if (seedEdgeInG0 && !seedEdgeInG1) {
            if (mu0.dotProduct(projectionVector) < mu1.dotProduct(projectionVector)) {
               projectionVector.mapMultiplyToSelf(-1.0);
            }
         } else if (seedEdgeInG1 && !seedEdgeInG0) {
            if (mu1.dotProduct(projectionVector) < mu0.dotProduct(projectionVector)) {
               projectionVector.mapMultiplyToSelf(-1.0);
            }
         } else {
            if ((!seedEdgeInG0 || !seedEdgeInG1) && !seedEdgeInG0) {
            }

            if (matrixG0.getRowDimension() < matrixG1.getRowDimension() && mu0.dotProduct(projectionVector) < mu1.dotProduct(projectionVector)) {
               projectionVector.mapMultiplyToSelf(-1.0);
            } else if (matrixG1.getRowDimension() < matrixG0.getRowDimension() && mu1.dotProduct(projectionVector) < mu0.dotProduct(projectionVector)) {
               projectionVector.mapMultiplyToSelf(-1.0);
            }
         }
      }
   }

   public static Double[] addX(Double[] arr, double x) {
      List<Double> arrlist = new ArrayList<>(Arrays.asList(arr));
      arrlist.add(x);
      return arrlist.toArray(arr);
   }

   private RealVector computeProjectionVector(RealMatrix matrixG0, RealMatrix matrixG1) {
      RealVector mu0 = new ArrayRealVector(new double[]{0.0, 0.0, 0.0});

      for (int i = 0; i < matrixG0.getRowDimension(); i++) {
         mu0 = mu0.add(matrixG0.getRowVector(i));
      }

      mu0.mapDivideToSelf((double)matrixG0.getRowDimension());
      RealVector mu1 = new ArrayRealVector(new double[]{0.0, 0.0, 0.0});

      for (int i = 0; i < matrixG1.getRowDimension(); i++) {
         mu1 = mu1.add(matrixG1.getRowVector(i));
      }

      mu1.mapDivideToSelf((double)matrixG1.getRowDimension());
      RealMatrix sw = new Array2DRowRealMatrix(3, 3);

      for (int i = 0; i < matrixG0.getRowDimension(); i++) {
         sw = sw.add(matrixG0.getRowVector(i).subtract(mu0).outerProduct(matrixG0.getRowVector(i).subtract(mu0)));
      }

      for (int i = 0; i < matrixG1.getRowDimension(); i++) {
         sw = sw.add(matrixG1.getRowVector(i).subtract(mu1).outerProduct(matrixG1.getRowVector(i).subtract(mu1)));
      }

      RealMatrix sb = mu0.subtract(mu1).outerProduct(mu0.subtract(mu1));
      DecompositionSolver solver = new SingularValueDecomposition(sw).getSolver();
      RealMatrix swInv = solver.getInverse();
      boolean isSwSingular = !solver.isNonSingular();
      RealVector projectionVector = null;
      if (isSwSingular) {
         if (matrixG0.getRowDimension() == 1) {
            matrixG1.getRowDimension();
         }

         RealVector projectionVectorCandidate1 = mu0.subtract(mu1);
         projectionVectorCandidate1.mapDivideToSelf(projectionVectorCandidate1.getNorm());
         double fisherObjectiveNumerator1 = this.fisherObjectiveNumerator(sb, projectionVectorCandidate1);
         RealVector projectionVectorCandidate2 = swInv.operate(mu0.subtract(mu1));
         projectionVectorCandidate2.mapDivideToSelf(projectionVectorCandidate2.getNorm());
         double fisherObjectiveNumerator2 = this.fisherObjectiveNumerator(sb, projectionVectorCandidate2);
         if (fisherObjectiveNumerator1 > fisherObjectiveNumerator2) {
            projectionVector = projectionVectorCandidate1;
         } else if (fisherObjectiveNumerator2 > fisherObjectiveNumerator1) {
            projectionVector = projectionVectorCandidate2;
         } else {
            projectionVector = projectionVectorCandidate1;
         }
      } else {
         projectionVector = swInv.operate(mu0.subtract(mu1));
         projectionVector.mapDivideToSelf(projectionVector.getNorm());
      }

      Assert.assertNotNull(projectionVector);
      return projectionVector;
   }

   private double fisherObjectiveNumerator(RealMatrix sb, RealVector v) {
      return sb.preMultiply(v).dotProduct(v);
   }

   private void printRealVector(RealVector vector) {
      int i = 0;

      while (i < vector.getDimension()) {
         i++;
      }
   }

   private void printRealMatrix(RealMatrix matrix) {
      for (int i = 0; i < matrix.getRowDimension(); i++) {
         int j = 0;

         while (j < matrix.getColumnDimension()) {
            j++;
         }
      }
   }

   private List<Cluster<EventEdgeWrapper>> clusterEdges(List<EventEdge> edges, String clusteringMethod) {
      List<EventEdgeWrapper> allEdgeWrappers = new ArrayList<>();

      for (EventEdge edge : edges) {
         allEdgeWrappers.add(new EventEdgeWrapper(edge, this.projectionFeatureLst));
      }

      List<Cluster<EventEdgeWrapper>> clusterResults = null;
      if (clusteringMethod.equals("kmeansPlusPlus")) {
         KMeansPlusPlusClusterer<EventEdgeWrapper> kmeansPlusPlusClusterer = new KMeansPlusPlusClusterer(2, 100000);
         clusterResults = new ArrayList<>(kmeansPlusPlusClusterer.cluster(allEdgeWrappers));
      } else if (clusteringMethod.equals("dbscan")) {
         DBSCANClusterer<EventEdgeWrapper> dbscanClusterer = new DBSCANClusterer(4.0, 1);
         clusterResults = dbscanClusterer.cluster(allEdgeWrappers);
      } else if (clusteringMethod.equals("multiKmeansPlusPlus")) {
         KMeansPlusPlusClusterer<EventEdgeWrapper> kmeansPlusPlusClusterer = new KMeansPlusPlusClusterer(2, 100000);
         MultiKMeansPlusPlusClusterer<EventEdgeWrapper> multiKmeansPlusPlusClusterer = new MultiKMeansPlusPlusClusterer(kmeansPlusPlusClusterer, 20);
         clusterResults = new ArrayList<>(multiKmeansPlusPlusClusterer.cluster(allEdgeWrappers));
      }

      this.printClusterResults(clusteringMethod, clusterResults);
      return clusterResults;
   }

   private void printClusterResults(String clusterMethod, List<Cluster<EventEdgeWrapper>> clusterResults) {
      for (int i = 0; i < clusterResults.size(); i++) {
         for (EventEdgeWrapper edgeWrapper : clusterResults.get(i).getPoints()) {
            EventEdge var6 = edgeWrapper.getEventEdge();
         }
      }
   }

   private void printEdgeWeights(EventEdge edge) {
      System.out
         .println(
            "EventEdge "
               + edge.getID()
               + " ("
               + edge.getSource().getId()
               + " "
               + edge.getSource().getSignature()
               + " ->"
               + edge.getEvent()
               + " "
               + edge.getSink().getId()
               + " "
               + edge.getSink().getSignature()
               + ")"
               + "\t timeWeight:"
               + this.timeWeights.get(edge.id)
               + " amountWeight: "
               + this.amountWeights.get(edge.id)
               + " structureWeight: "
               + this.structureWeights.get(edge.id)
               + " finalWeight: "
               + this.weights.get(edge.id)
         );
   }

   public void initialReputation(String[] signature_high, String[] signature_neutral, String[] signature_low) {
      Set<EntityNode> set = this.graph.vertexSet();
      Set<String> highReputation = new HashSet<>(Arrays.asList(signature_high));
      Set<String> lowReputation = new HashSet<>(Arrays.asList(signature_low));

      for (EntityNode node : set) {
         if (highReputation.contains(node.getSignature())) {
            node.reputation = 1.0;
         } else if (lowReputation.contains(node.getSignature())) {
            node.reputation = 0.0;
         } else if (this.graph.incomingEdgesOf(node).size() == 0) {
            node.reputation = 0.0;
         }
      }
   }

   public void initialReputation(DirectedPseudograph<EntityNode, EventEdge> jg, String[] signature_high, String[] signature_neutral, String[] signature_low) {
      Set<EntityNode> set = jg.vertexSet();
      Set<String> highReputation = new HashSet<>(Arrays.asList(signature_high));
      Set<String> lowReputation = new HashSet<>(Arrays.asList(signature_low));

      for (EntityNode node : set) {
         if (highReputation.contains(node.getSignature())) {
            node.reputation = 1.0;
         } else if (lowReputation.contains(node.getSignature())) {
            node.reputation = 0.0;
         } else if (this.graph.incomingEdgesOf(node).size() == 0) {
            node.reputation = 0.0;
         }
      }
   }

   public void PageRankIteration(String detection) {
      long start = System.currentTimeMillis();
      Set<EntityNode> vertexSet = this.graph.vertexSet();
      double fluctuation = 1.0;
      int iterTime = 0;

      while (fluctuation >= 1.0E-13) {
         double culmativediff = 0.0;
         iterTime++;
         Map<Long, Double> preReputation = this.getReputation();

         for (EntityNode v : vertexSet) {
            if (!v.getSignature().equals(detection)) {
               double rep = 0.0;
               Set<EventEdge> edges = this.graph.outgoingEdgesOf(v);
               if (edges.size() != 0) {
                  for (EventEdge edge : edges) {
                     EntityNode childNode = edge.getSink();
                     rep += preReputation.getOrDefault(childNode.getId(), 0.0) * this.weights.getOrDefault(edge.id, 0.0);
                  }

                  culmativediff += Math.abs(rep - preReputation.getOrDefault(v.getId(), 0.0));
                  v.reputation = rep;
               }
            }
         }

         fluctuation = culmativediff;
      }

      long end = System.currentTimeMillis();
      double timeCost = (double)(end - start) * 1.0 / 1000.0;
   }

   public void PageRankIteration(DirectedPseudograph<EntityNode, EventEdge> jg, String detection) {
      long start = System.currentTimeMillis();
      Set<EntityNode> vertexSet = jg.vertexSet();
      double fluctuation = 1.0;
      int iterTime = 0;

      while (fluctuation >= 1.0E-13) {
         double culmativediff = 0.0;
         iterTime++;
         Map<Long, Double> preReputation = this.getReputation(jg);

         for (EntityNode v : vertexSet) {
            if (!v.getSignature().equals(detection)) {
               double rep = 0.0;
               Set<EventEdge> edges = jg.outgoingEdgesOf(v);
               if (edges.size() != 0) {
                  for (EventEdge edge : edges) {
                     EntityNode childNode = edge.getSink();
                     rep += preReputation.getOrDefault(childNode.getId(), 0.0) * this.weights.getOrDefault(edge.id, 0.0);
                  }

                  culmativediff += Math.abs(rep - preReputation.getOrDefault(v.getId(), 0.0));
                  v.reputation = rep;
               }
            }
         }

         fluctuation = culmativediff;
      }

      long end = System.currentTimeMillis();
      double timeCost = (double)(end - start) * 1.0 / 1000.0;
   }

   public void PageRankIterationBackward(String[] highRP) {
      Set<EntityNode> vertexSet = this.graph.vertexSet();
      Set<String> sources = new HashSet<>(Arrays.asList(highRP));
      double fluctuation = 1.0;
      int iterTime = 0;

      while (fluctuation >= 1.0E-13) {
         double culmativediff = 0.0;
         iterTime++;
         Map<Long, Double> preReputation = this.getReputation();

         for (EntityNode v : vertexSet) {
            if (!sources.contains(v.getSignature())) {
               Set<EventEdge> edges = this.graph.outgoingEdgesOf(v);
               double rep = 0.0;

               for (EventEdge edge : edges) {
                  EntityNode sink = edge.getSink();
                  rep += preReputation.get(sink.getId()) * this.weights.get(edge.id);
               }

               culmativediff += Math.abs(rep - preReputation.get(v.getId()));
               v.setReputation(rep);
            }
         }

         fluctuation = culmativediff;
      }

      System.out.println(String.format("After %d times iteration, the reputation of each vertex is stable", iterTime));
   }

   public void RandomRankAssignment() {
      Set<EntityNode> vertexSet = this.graph.vertexSet();
      Random random = new Random();

      for (EntityNode v : vertexSet) {
         double randomRank = random.nextDouble();
         v.setReputation(randomRank);
      }

   }

   public void ApplySigmoid() {
      Set<EntityNode> vertexSet = this.graph.vertexSet();
      double beta = 1.0;

      for (EntityNode v : vertexSet) {
         v.setReputation(1.0 / (1.0 + Math.exp(-(v.getReputation() - beta))));
      }
   }

   private Map<Long, Double> getReputation() {
      Set<EntityNode> vertexSet = this.graph.vertexSet();
      Map<Long, Double> map = new HashMap<>();

      for (EntityNode node : vertexSet) {
         map.put(node.getId(), node.getReputation());
      }

      return map;
   }

   private Map<Long, Double> getReputation(DirectedPseudograph<EntityNode, EventEdge> jg) {
      Set<EntityNode> vertexSet = jg.vertexSet();
      Map<Long, Double> map = new HashMap<>();

      for (EntityNode node : vertexSet) {
         map.put(node.getId(), node.getReputation());
      }

      return map;
   }

   private List<Double> computeFinalWeights_Individual(List<EventEdge> allEdges, String weightType) {
      System.out.println("computeFinalWeights_Individual invoked!");
      List<Double> finalWeights = new ArrayList<>();

      for (int i = 0; i < allEdges.size(); i++) {
         finalWeights.add(0.0);
      }

      for (EntityNode n : this.graph.vertexSet()) {
         List<EventEdge> inEdges = new ArrayList<>(this.graph.incomingEdgesOf(n));
         if (inEdges.size() != 0) {
            if (inEdges.size() == 1) {
               finalWeights.set(allEdges.indexOf(inEdges.get(0)), 1.0);
            } else if (weightType == null) {
               for (EventEdge edge : inEdges) {
                  finalWeights.set(allEdges.indexOf(edge), edge.timeWeight);
               }
            } else if (weightType.equals("time")) {
               for (EventEdge edge : inEdges) {
                  finalWeights.set(allEdges.indexOf(edge), edge.timeWeight);
               }
            } else if (weightType.equals("amount")) {
               for (EventEdge edge : inEdges) {
                  finalWeights.set(allEdges.indexOf(edge), edge.amountWeight);
               }
            } else if (weightType.equals("structure")) {
               for (EventEdge edge : inEdges) {
                  finalWeights.set(allEdges.indexOf(edge), edge.structureWeight);
               }
            } else {
               System.out.println("Unsupported weightType: " + weightType);
            }
         }
      }

      return finalWeights;
   }

   public void calculateWeights_SingleFeature_Only(String featureType, boolean normalizeByOutEdges) {
      long start = System.currentTimeMillis();
      Set<EntityNode> vertexSet = this.graph.vertexSet();
      Map<Long, Double> singleWeights = new HashMap<>();
      ProjectionFeature feature = this.projectionFeatureLst.stream().filter(f -> f.getFeatureType().equals(featureType)).findAny().orElse(null);
      if (feature == null) {
         System.out.println("Unsupported feature type: " + featureType);
      } else {
         for (EntityNode n : vertexSet) {
            for (EventEdge inEdge : this.graph.incomingEdgesOf(n)) {
               singleWeights.put(inEdge.id, this.getFeatureWeight(inEdge, feature));
            }
         }

         for (EntityNode node : vertexSet) {
            double total = 0.0;

            for (EventEdge e : this.graph.outgoingEdgesOf(node)) {
               total += singleWeights.getOrDefault(e.id, 0.0);
            }

            if (total > 1.0E-8) {
               for (EventEdge e : this.graph.outgoingEdgesOf(node)) {
                  double normalized = singleWeights.getOrDefault(e.id, 0.0) / total;
                  singleWeights.put(e.id, normalized);
               }
            }
         }

         for (EntityNode n : vertexSet) {
            for (EventEdge inEdge : this.graph.incomingEdgesOf(n)) {
               double val = singleWeights.getOrDefault(inEdge.id, 0.0);
               if (featureType.equals("amount")) {
                  inEdge.amountWeight = val;
               } else if (featureType.equals("time")) {
                  inEdge.timeWeight = val;
               } else if (featureType.equals("structure")) {
                  inEdge.structureWeight = val;
               }
            }
         }

         List<EventEdge> allEdges = new ArrayList<>(this.graph.edgeSet());
         List<Double> finalWeights = new ArrayList<>();

         for (EventEdge e : allEdges) {
            double val = 0.0;
            if (featureType.equals("amount")) {
               val = e.amountWeight;
            } else if (featureType.equals("time")) {
               val = e.timeWeight;
            } else if (featureType.equals("structure")) {
               val = e.structureWeight;
            }

            finalWeights.add(val);
         }

         List<EventEdgeWrapper> wrappedEdges = new ArrayList<>();

         for (int i = 0; i < allEdges.size(); i++) {
            wrappedEdges.add(new EventEdgeWrapper(allEdges.get(i), new double[]{finalWeights.get(i)}));
         }

         KMeansPlusPlusClusterer<EventEdgeWrapper> clusterer = new KMeansPlusPlusClusterer(2, 100000);
         List<Cluster<EventEdgeWrapper>> clusters = new ArrayList<>(clusterer.cluster(wrappedEdges));
         double[] means = new double[2];

         for (int i = 0; i < clusters.size(); i++) {
            double sum = 0.0;

            for (EventEdgeWrapper ew : clusters.get(i).getPoints()) {
               sum += ew.getPoint()[0];
            }

            means[i] = sum / (double)clusters.get(i).getPoints().size();
         }

         double projectionVector = means[1] - means[0];
         List<Double> projectedWeights = new ArrayList<>();

         for (double w : finalWeights) {
            projectedWeights.add(w * projectionVector);
         }

         double min = Collections.min(projectedWeights);
         double max = Collections.max(projectedWeights);
         double range = max - min;

         for (int i = 0; i < projectedWeights.size(); i++) {
            if (range > 1.0E-8) {
               projectedWeights.set(i, (projectedWeights.get(i) - min) / range);
            } else {
               projectedWeights.set(i, 0.0);
            }
         }

         for (int ix = 0; ix < allEdges.size(); ix++) {
            allEdges.get(ix).weight = projectedWeights.get(ix);
         }

         for (EntityNode n : vertexSet) {
            double total = 0.0;

            for (EventEdge out : this.graph.outgoingEdgesOf(n)) {
               total += out.weight;
            }

            if (total > 1.0E-8) {
               for (EventEdge out : this.graph.outgoingEdgesOf(n)) {
                  out.weight = out.weight / total * 0.99;
                  this.weights.put(out.id, out.weight);
               }
            }
         }

         long end = System.currentTimeMillis();
      }
   }
}
