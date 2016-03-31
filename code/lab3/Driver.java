/**
 *
 * @file: Driver.java
 * @author: Anthony Cali
 * @course: MSCS 630 Security Algorithms and Protocols
 * @assignment: Lab 3
 * @due date: March 31, 2016
 * @version: 1.0
 *
 * @abstract: Entry point Driver class file.
 */

import java.util.Scanner;

/**
 *
 * Driver class used for testing purposes also functions as the entry point.
 */
public class Driver {
  /**
   *
   * main entry point method.
   * @param args, The CLI args if used.
   * @return void, Prints the results to System.out.
   */
  public static void main(String args[]) {
    Scanner input = new Scanner(System.in);
    String key = input.nextLine();
    String text = input.nextLine();
    AEScipher cipher = new AEScipher();
    String cTextHex = cipher.aes(text,key);
    System.out.println(cTextHex);
  }
}
