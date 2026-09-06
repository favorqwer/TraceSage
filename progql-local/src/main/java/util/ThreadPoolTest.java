package util;

public class ThreadPoolTest {
   public static void main(String[] args) {
      try {
         System.out.print(args[0]);
         Thread.sleep(10000L);
      } catch (InterruptedException var2) {
         var2.printStackTrace();
      }
   }
}
