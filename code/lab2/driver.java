/**
 *
 *
 */

import java.util.Scanner;

/**
 * driver class used for testing purposes also functions as the entry point.
 */
public class driver {
  /**
   * main entry point method.
   * @param args, The CLI args if used.
   * @return void, Prints the results to System.out.
   */
  public void main(String args[]) {
    Scanner input = new Scanner(System.in);
    String key = input.next();
    String[] roundKeysHex = aescipher.aesRoundKeys(key);
    for(String outKey : roundKeysHex) {
      System.out.println(outKey);
    }
  }
}
