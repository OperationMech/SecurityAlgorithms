/**
 * @file: Driver.java
 * @author: Anthony Cali
 * @course: MSCS 630 Security Algorithms and Protocols
 * @assignment: Project
 * @due date: May 2, 2016
 * @version: 1.0
 * @abstract: Entry point Driver class file.
 */

import java.util.Scanner;

/**
 *
 * Driver class used as entrypoint.
 */
public class Driver {
  /**
   * main entrypoint function.
   * @param args, Command Line arguments.
   * @retun void, Prints the output to System.out.
   */
  public static void main(String[] args) {
    Scanner input = new Scanner(System.in);
    String key = input.nextLine();
    String initVector = input.nextLine();
    String argument = input.nextLine();
    String text = "";
    while(input.hasNext()) {
      text = text + input.nextLine();
    }

    char[] charKey = processString(key);
    char[] charIV = processString(initVector);
    char[] charText = processString(text);
    if(argument.equals("encrypt")) {
      // Safety try block for destruction of the cipher.
      try {
        MatrixCipher matrixCiph = new MatrixCipher();
        System.out.print(matrixCiph.encrypt(charKey, charIV, charText));
      } catch (Exception e) {
      }
    } else if(argument.equals("decrypt")) {
      // Safety try block for destruction of the cipher.
      try {
      } catch (Exception e) {
      }
    } else {
      System.out.println("USAGE: driver [e/d/encrypt/decrypt] << <input.txt>.");
    }
  }

  /**
   *
   * processString method for turning a String into a character array.
   * @param input, The input string to convert.
   * @return char[], The resultant character array.
   */
  public static char[] processString(String input) {
    char[] out = null;
    input.getChars(0, input.length(), out, 0);
    return out;
  }
}