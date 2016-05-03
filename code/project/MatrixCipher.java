/**
 * @file: MatrixCipher.java
 * @author: Anthony Cali
 * @course: MSCS 630 Security Algorithms and Protocols
 * @assignment: Project
 * @due date: May 2, 2016
 * @version: 1.0
 * @abstract: Entry point Driver class file.
 */

import java.lang.Character;
import java.util.ArrayList;
import java.util.List;

/**
 * MatrixCipher class and implementation.
 */
public class MatrixCipher {
  // Local class variables.
  private byte[] stateMatrix = new byte[36];
  private byte[] originalKey = new byte[36];
  private byte[] text = {};
  private List<byte[]> roundKeys = new ArrayList<>();
  private static final byte[] TRIANGLE_MATRIX = {
    1, 1, 1, 1, 1, 1,
    0, 1, 1, 1, 1, 1,
    0, 0, 1, 1, 1, 1,
    0, 0, 0, 1, 1, 1,
    0, 0, 0, 0, 1, 1,
    0, 0, 0, 0, 0, 1};

  /**
   * setText method sets the private text field.
   *
   * @param input, The character array input.
   */
  private void setText(char[] input) {
    int i = 0;
    byte[] localBytes = new byte[input.length];
    while (i < input.length) {
      localBytes[i] = bitwiseEndianShift((byte) Character.getNumericValue(input[i]));
      i++;
    }
    text = localBytes;
  }

  /**
   * setTextDecrypt method sets the private text field.
   *
   * @param input, The character array input.
   */
  private void setTextDecrypt(char[] input) {
    int i = 0;
    byte[] localBytes = new byte[input.length];
    while (i < input.length) {
      localBytes[i] = (byte) Character.getNumericValue(input[i]);
      i++;
    }
    text = localBytes;
  }

  /**
   * setOrigKey method sets the private key field.
   *
   * @param input, The character array input.
   */
  private void setOrigKey(char[] input) {
    int i = 0;
    int j = 0;
    byte[] localBytes = new byte[(input.length / 2)];
    while (i < input.length) {
      char[] localByteChars = {input[i], input[i + 1]};
      localBytes[j] = bitwiseEndianShift(charByteToByte(localByteChars, 16));
      j++;
      i = i + 2;
    }
    for (i = 0; i < localBytes.length; i++) {
      originalKey[i] = localBytes[i];
    }
    roundKeys.add(originalKey);
  }

  /**
   * MatrixCipher constructor used for resolving existence issues.
   */
  public MatrixCipher() {
  }

  /**
   * charByteToByte method takes a 2 character representation
   * of a byte into a byte.
   *
   * @param radix, The numeric range for the conversion.
   * @return byte, The byte from the characters.
   */
  private byte charByteToByte(char[] nybbles, int radix) {
    byte first = (byte) Character.digit(nybbles[0], radix);
    return (byte) ((first << 4) + Character.digit(nybbles[1], radix));
  }

  /**
   * maskAndShiftByte method alters the bit order of the input
   * byte by the shift according to the mask.
   *
   * @param input, The byte input.
   * @param mask,  The bitmask.
   * @param shift, The shift amount.
   * @return integer, the reversed byte.
   */
  private int maskAndShiftByte(byte input, int mask, int shift) {
    if (shift < 0) {
      return (input & mask) << -shift;
    } else {
      return (input & mask) >>> shift;
    }
  }

  /**
   * bitwiseEndianShift method flips the bit order of the input byte.
   *
   * @param input, The input byte to be endian shifted.
   * @return byte, The output endian shifted byte.
   */
  private byte bitwiseEndianShift(byte input) {

    byte left = (byte) (
      (maskAndShiftByte(input, 0x80, 7) +
      maskAndShiftByte(input, 0x40, 5)) +
      (maskAndShiftByte(input, 0x20, 3) +
      maskAndShiftByte(input, 0x10, 1)));

    byte right = (byte) (
      (maskAndShiftByte(input, 0x80, -7) +
      maskAndShiftByte(input, 0x40, -5)) +
      (maskAndShiftByte(input, 0x20, -3) +
      maskAndShiftByte(input, 0x10, -1)));
    return (byte) (left ^ right);
  }

  /**
   * generateRoundKeys method creates the six round keys used in encryption / decryption.
   */
  private void generateRoundKeys() {
    byte rotateLeft = 1;
    byte flip180 = 2;
    byte applyLowerTriangle = 3;
    byte rotate270Left = 4;
    roundKeys.add(xorMatrices(originalKey, rotateMatrixLeft(originalKey)));
    originalKey[32] = rotateLeft;
    roundKeys.add(
      xorMatrices(roundKeys.get(roundKeys.size() - 1),
        rotateMatrixLeft(rotateMatrixLeft(originalKey))
      )
    );
    originalKey[33] = flip180;
    roundKeys.add(
      xorMatrices(roundKeys.get(roundKeys.size() - 1),
        applyTriangleMatrix(originalKey)
      )
    );
    originalKey[34] = applyLowerTriangle;
    roundKeys.add(
      xorMatrices(roundKeys.get(roundKeys.size() - 1),
        rotateMatrixRight(originalKey)
      )
    );
    originalKey[35] = rotate270Left;
    roundKeys.add(
      xorMatrices(roundKeys.get(roundKeys.size() - 1), originalKey)
    );
  }

  /**
   * xorMatrices method XORS two matrices.
   *
   * @param inputA, Matrix input A.
   * @param inputB, Matrix input B.
   * @return byte[], Matrix A XOR Matrix B.
   */
  private byte[] xorMatrices(byte[] inputA, byte[] inputB) {
    byte[] output = new byte[inputA.length];
    for (int i = 0; i < inputA.length; i++) {
      output[i] = (byte) (inputA[i] ^ inputB[i]);
    }
    return output;
  }

  /**
   * applyTriangleMatrix method takes the input matrix and
   * bitwise ands it with the defined triangle matrix.
   *
   * @param input, The matrix which the triangle will be applied to.
   * @return byte[], The output matrix after Matrix input & Triangle.
   */
  private byte[] applyTriangleMatrix(byte[] input) {
    byte[] output = new byte[input.length];
    for (int i = 0; i < input.length; i++) {
      output[i] = (byte) (input[i] & TRIANGLE_MATRIX[i]);
    }
    return output;
  }

  /**
   * rotateMatrixLeft method to rotate a matrix to the left by 90 degrees.
   *
   * @param input, The byte matrix input.
   * @return byte[], The output matrix.
   */
  private byte[] rotateMatrixLeft(byte[] input) {
    byte[] output = new byte[input.length];
    for (int i = 0; i < 6; i++) {
      output[(i % 6) + 30] = input[i];
    }
    for (int i = 6; i < 12; i++) {
      output[(i % 6) + 24] = input[i];
    }
    for (int i = 12; i < 18; i++) {
      output[(i % 6) + 18] = input[i];
    }
    for (int i = 18; i < 24; i++) {
      output[(i % 6) + 12] = input[i];
    }
    for (int i = 24; i < 30; i++) {
      output[(i % 6) + 6] = input[i];
    }
    for (int i = 30; i < 36; i++) {
      output[(i % 6)] = input[i];
    }
    return output;
  }

  /**
   * rotateMatrixRight method to rotate a matrix to the right by 90 degrees.
   *
   * @param input, The byte matrix input.
   * @return byte[], The output matrix.
   */
  private byte[] rotateMatrixRight(byte[] input) {
    byte[] output = new byte[input.length];
    for (int i = 30; i < 36; i++){
      output[35 - (i % 6)] = input[i];
    }
    for (int i = 24; i < 30; i++){
      output[29 - (i % 6)] = input[i];
    }
    for (int i = 18; i < 24; i++){
      output[23 - (i % 6)] = input[i];
    }
    for (int i = 12; i < 18; i++){
      output[17 - (i % 6)] = input[i];
    }
    for (int i = 6; i < 12; i++){
      output[11 - (i % 6)] = input[i];
    }
    for (int i = 0; i < 6; i++){
      output[5 - (i % 6)] = input[i];
    }
    return output;
  }

  /**
   * bytesToString method converts an input byte array into a string.
   * @param input, The input byte array to convert.
   * @return String, The output string from the bytes.
   */
  private String bytesToString(byte[] input) {
    String output = "";
    for (int i = 0; i < input.length; i++) {
      output = output + Integer.toHexString((byte) input[i]);
    }
    return output;
  }

  /**
   *
   * encrypt method for MatrixCipher.
   * @param key, The key for encrypting.
   * @param initVector, The cbc-mode initializing vector.
   * @param message, The plaintext to be encrypted.
   * @return String, The ciphertext which is encrypted.
   */
  public String encrypt(char[] key, char[] initVector, char[] message) {
    String output = "";
    byte[] localVectorBytes = new byte[(initVector.length / 2)];
    int j = 0;
    for (int i = 0; i < localVectorBytes.length; i = i + 2, j++) {
      char[] localVecChars = {initVector[i], initVector[i+1]};
      localVectorBytes[j] = bitwiseEndianShift(charByteToByte(localVecChars, 16));
    }

    setOrigKey(key);
    setText(message);

    generateRoundKeys();

    int i = 0;
    int blocks = 0;
    while (blocks < (text.length / 32)) {
      stateMatrix[i % 32] = text[i];
      if (i+1 % 32 == 0) {
        stateMatrix = xorMatrices(roundKeys.get(0), stateMatrix);
        stateMatrix = xorMatrices(roundKeys.get(1), stateMatrix);
        stateMatrix = xorMatrices(roundKeys.get(2), stateMatrix);
        stateMatrix = xorMatrices(roundKeys.get(3), stateMatrix);
        stateMatrix = xorMatrices(roundKeys.get(4), stateMatrix);
        stateMatrix = xorMatrices(localVectorBytes, stateMatrix);
        stateMatrix = xorMatrices(roundKeys.get(5), stateMatrix);
        localVectorBytes = stateMatrix;
        output = output + bytesToString(stateMatrix);
        blocks++;
      }
      i++;
    }
    return output;
  }

  /**
   *
   * decrypt method for MatrixCipher.
   * @param key, The key for decrypting.
   * @param initVector, The cbc-mode initializing vector.
   * @param message, The ciphertext to be decrypted.
   * @return String, The plaintext which is decrypted.
   */
  public String decrypt(char[] key, char[] initVector, char[] message) {
    String output = "";
    byte[] localVectorBytes = new byte[(initVector.length / 2)];
    int j = 0;
    for (int i = 0; i < localVectorBytes.length; i = i + 2, j++) {
      char[] localVecChars = {initVector[i], initVector[i + 1]};
      localVectorBytes[j] = bitwiseEndianShift(charByteToByte(localVecChars, 16));
    }

    setOrigKey(key);
    setTextDecrypt(message);

    generateRoundKeys();
    int i = 0;
    int blocks = 0;
    while ( blocks <  (text.length / 32)) {
      stateMatrix[i % 32] = text[i];
      if(i+1 % 32 == 0) {
        stateMatrix = xorMatrices(roundKeys.get(5), stateMatrix);
        stateMatrix = xorMatrices(localVectorBytes, stateMatrix);
        stateMatrix = xorMatrices(roundKeys.get(4), stateMatrix);
        stateMatrix = xorMatrices(roundKeys.get(3), stateMatrix);
        stateMatrix = xorMatrices(roundKeys.get(2), stateMatrix);
        stateMatrix = xorMatrices(roundKeys.get(1), stateMatrix);
        stateMatrix = xorMatrices(roundKeys.get(0), stateMatrix);
        localVectorBytes = stateMatrix;
        for(j = 0; j < 32; j++) {
          stateMatrix[j] = bitwiseEndianShift(stateMatrix[j]);
        }
        output = output + bytesToString(stateMatrix);
        blocks++;
      }
      i++;
    }
    return output;
  }
}