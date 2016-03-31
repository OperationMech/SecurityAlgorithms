/**
 *
 * @file: AEScipher.java
 * @author: Anthony Cali
 * @course: MSCS 630 Security Algorithms and Protocols
 * @assignment: Lab 2
 * @due date: March 31, 2016
 * @version: 0.8
 *
 * @abstract: Aescipher class file; This file contains all the neccessary
 *              functions for the AES cipher.
 */

/**
 * aescipher class implements the AES algorithm and all helper functions.
 */
public class AEScipher {
  /**
   *
   * Public constructor prevents existence issues.
   */
  public AEScipher() {};
  // Work matrix W.
  private String[][] WMatrix = new String[4][44];
  // S-Box mappings.
  private String[][] S_BOX = {
    {"63","7C","77","7B","F2","6B","6F","C5","30","01","67","2B","FE","D7","AB","76"},
    {"CA","82","C9","7D","FA","59","47","F0","AD","D4","A2","AF","9C","A4","72","C0"},
    {"B7","FD","93","26","36","3F","F7","CC","34","A5","E5","F1","71","D8","31","15"},
    {"04","C7","23","C3","18","96","05","A9","07","12","80","E2","EB","27","B2","75"},
    {"09","83","2C","1A","1B","6E","5A","A0","52","3B","D6","B3","29","E3","2F","84"},
    {"53","D1","00","ED","20","FC","B1","5B","6A","CB","BE","39","4A","4C","58","CF"},
    {"D0","EF","AA","FB","43","4D","33","85","45","F9","02","7F","50","3C","9F","A8"},
    {"51","A3","40","8F","92","9D","38","F5","BC","B6","DA","21","10","FF","F3","D2"},
    {"CD","0C","13","EC","5F","97","44","17","C4","A7","7E","3D","64","5D","19","73"},
    {"60","81","4F","DC","22","2A","90","88","46","EE","B8","14","DE","5E","0B","DB"},
    {"E0","32","3A","0A","49","06","24","5C","C2","D3","AC","62","91","95","E4","79"},
    {"E7","C8","37","6D","8D","D5","4E","A9","6C","56","F4","EA","65","7A","AE","08"},
    {"BA","78","25","2E","1C","A6","B4","C6","E8","DD","74","1F","4B","BD","8B","8A"},
    {"70","3E","B5","66","48","03","F6","0E","61","35","57","B9","86","C1","1D","9E"},
    {"E1","F8","98","11","69","D9","8E","94","9B","1E","87","E9","CE","55","28","DF"},
    {"8C","A1","89","0D","BF","E6","42","68","41","99","2D","0F","B0","54","BB","16"}};
  // Round constants shortened to discovered repeat point.
  private String[] R_CON = {
    "8D","01","02","04","08","10","20","40","80","1B",
    "36","6C","D8","AB","4D","9A","2F","5E","BC","63",
    "C6","97","35","6A","D4","B3","7D","FA","EF","C5",
    "91","39","72","E4","D3","BD","61","C2","9F","25",
    "4A","94","33","66","CC","83","1D","3A","74","E8",
    "CB"};
  // State Matrix
  private byte[][] stateMatrix = new byte[4][4];
  // RoundKey XOR Matrix
  private byte[][] keyInXOR = new byte[4][4];

  /**
   *
   * aesRoundKeys method finds the round keys for use in
   *  AES encryption/decryption rounds.
   *
   * @param HexKey: The input key as a string for AES which is
   *                  transcribed into the round keys.
   *
   * @return String[]: The constructed round keys in a string array.
   */
  private String[] aesRoundKeys(String HexKey) {
    String[] output = new String[11];
    output[0] = HexKey;
    String[] bytes = new String[16];
    int count = 0;
    for(int i = 0; i < HexKey.length()-1; i+=2) {
      bytes[count] = HexKey.substring(i, i+2);
      count++;
    }
    int columns = 4;
    int rows = 4;
    int index = 0;
    for(int i = 0; i < columns; i++) {
      for(int j = 0; j < rows; j++) {
        WMatrix[j][i] = bytes[index];
        index++;
      }
    }
    columns = 44;
    int BlockLength = 4;
    int roundNum = 0;
    for(int i = 4; i < columns; i++) {
      // The column is a multiple of 4.
      if(i % BlockLength == 0) {
        roundNum++;
        String[] WNew = {"","","",""};
        // Make a new SBoxed vector and shift it by one left.
        for (int j = 0; j < rows; j++) {
          if(j == 0) {
            WNew[j+3] = aesSBox(WMatrix[j][i-1]);
          } else {
            WNew[j-1] = aesSBox(WMatrix[j][i-1]);
          }
        }
        Integer Rcon = Integer.parseInt(aesRcon(roundNum),16);
        Integer WPrimeS0 = Integer.parseInt(WNew[0],16);
        Integer WNewPrime = Rcon ^ WPrimeS0;
        if(WNewPrime < 16) {
          WNew[0] = "0" + Integer.toHexString(WNewPrime);
        } else {
          WNew[0] = Integer.toHexString(WNewPrime);
        }
        // W(j-4 XOR WNew)
        for (int j = 0; j < rows; j++) {
          Integer WjFourLess = Integer.parseInt(WMatrix[j][i-4],16);
          Integer WjNew = Integer.parseInt(WNew[j],16);
          Integer WMPrime = WjFourLess ^ WjNew;
          String WMNew = "";
          if(WMPrime < 16) {
            WMNew = "0" + Integer.toHexString(WMPrime);
          } else {
            WMNew = Integer.toHexString(WMPrime);
          }
          WMatrix[j][i] = WMNew.toUpperCase();
        }
      } else {
        // W(j-4) XOR W(j-1)
        for (int j = 0; j < rows; j++) {
          Integer WjFourLess = Integer.parseInt(WMatrix[j][i-4],16);
          Integer WjOneLess = Integer.parseInt(WMatrix[j][i-1],16);
          Integer WjPrime = WjFourLess ^ WjOneLess;
          if(WjPrime < 16) {
            WMatrix[j][i] = "0" + Integer.toHexString(WjPrime).toUpperCase();
          } else {
            WMatrix[j][i] = Integer.toHexString(WjPrime).toUpperCase();
          }
        }
      }
    }
    roundNum = 0;
    for(int i = 4; i < columns; i++) {
      int prevRoundNum = roundNum;
      if(i % BlockLength == 0) {
        roundNum++;
      }
      for(int j = 0; j < rows; j++) {
        if(prevRoundNum != roundNum && j == 0){
          output[roundNum] = WMatrix[j][i];
        } else {
          output[roundNum] += WMatrix[j][i];
        }
      }
    }
    return output;
  }

  /**
   *
   * aesSBox method determines the mapping for the input value.
   *
   * @param inHex: The input string used to determine the row from
   *                 the low-order bits and col from high-order bits.
   *
   * @return String: The mapped value of the input value.
   */
  private String aesSBox(String inHex) {
    String output = "";
    int[] bits = {0,0};
    for(int i = 0; i < inHex.length(); i++) {
      bits[i] = Integer.parseInt(inHex.substring(i,i+1),16);
    }
    output = S_BOX[bits[0]][bits[1]];
    return output;
  }

  /**
   *
   * aesRcon method looks up the specific round constant using R_CON.
   *
   * @param round: The current round for AES.
   *
   * @return String: The round constant for the round.
   */
  private String aesRcon(int round) {
    int roundsToRepeat = 51;
    String output = R_CON[round % roundsToRepeat];
    return output;
  }

  /**
   *
   * aesStateXOR method combines the round key with the state matrix
   *
   * @param sHex: The state matrix.
   * @param keyHex: The round key matrix.
   *
   * @return byte matrix: The XOR result state matrix.
   */
  private byte[][] aesStateXOR(byte[][] sHex, byte[][] keyHex) {
    byte[][] output = new byte[4][4];
    for(int rows = 0; rows < 4; rows++) {
      for(int cols = 0; cols < 4; cols++) {
        output[rows][cols] = (byte)(sHex[rows][cols] ^ keyHex[rows][cols]);
      }
    }
    return output;
  }

  /**
   *
   * aesNibbleSub method uses the SBox lookup table to
   *              scramble the state matrix.
   *
   * @param inStateHex: The state matrix input.
   *
   * @return byte[][]: The resultant state matrix.
   */
  private byte[][] aesNibbleSub(byte[][] inStateHex) {
    String lookupVal = "";
    byte[][] output = new byte[4][4];
    for(int rows = 0; rows < 4; rows++) {
      for(int cols = 0; cols < 4; cols++) {
        System.out.println(inStateHex[rows][cols]);
        if(inStateHex[rows][cols] < 16) {
          lookupVal = "0" + Integer.toHexString(inStateHex[rows][cols] & 0xFF);
        } else {
          lookupVal = Integer.toHexString(inStateHex[rows][cols] & 0xFF);
        }
        lookupVal = lookupVal.toUpperCase();
        System.out.println(lookupVal);
        lookupVal = aesSBox(lookupVal);
        output[rows][cols] =
          (byte)((stringToByte(lookupVal.substring(0,1)) * 16) +
                 stringToByte(lookupVal.substring(1,2)));
      }
    }
    return output;
  }

  /**
   *
   * aesShiftRow method shifts the rows by 1, then 2, and finally 3.
   *
   * @param inStateHex: The state matrix input.
   *
   * @return byte[][]: The resultant state matrix.
   */
  private byte[][] aesShiftRow(byte[][] inStateHex) {
    int row = 1;
    byte[][] output = new byte[4][4];
    for(int col = 0; col < 4; col++ ) {
      if(col == 0) {
        output[row][col+3] = inStateHex[row][col];
      } else {
        output[row][col-1] = inStateHex[row][col];
      }
    }
    row++;
    for(int col = 0; col < 4 - row; col++) {
      output[row][col+2] = inStateHex[row][col];
      output[row][col] = inStateHex[row][col+2];
    }
    row++;
    for(int col = 0; col < 4; col++) {
      output[row][col+1%4] = inStateHex[row][col];
    }
    return output;
  }

  /**
   *
   * aesMixColumn method mixes the columns in the state matrix.
   *
   * @param inStateHex: The state matrix input.
   *
   * @return byte[][]: The resultant state matrix.
   */
  private byte[][] aesMixColumn(byte[][] inStateHex) {
    byte[][] output = new byte[4][4];
    for(int rows = 0; rows < 4; rows++) {
      output[rows] = gfMult(inStateHex[rows]);
    }
    return output;
  }

  /**
   *
   * gfMult method for AES mix column matrix math.
   *
   * @param inVecHex: Column for mixing.
   *
   * @return byte[]: Mixed column.
   */
  private byte[] gfMult(byte[] inVecHex) {
    byte[] output = new byte[4];
    byte[] copy = new byte[4];
    byte[] gfFactor = new byte[4];
    byte overflow;
    int overflowVal = 0x1b;
    for(int index = 0; index < 4; index++) {
      copy[index] = inVecHex[index];
      overflow = (byte)(inVecHex[index] >> 7);
      gfFactor[index] = (byte)(inVecHex[index] << 1);
      gfFactor[index] = (byte)(gfFactor[index] ^ overflow & overflowVal);
    }
    output[0] = (byte)(gfFactor[0] ^ (gfFactor[1] ^ copy[1]) ^ copy[2] ^ copy[3]);
    output[1] = (byte)(copy[0] ^ gfFactor[1] ^ (gfFactor[2] ^ copy[2]) ^ copy[3]);
    output[2] = (byte)(copy[0] ^ copy[1] ^ gfFactor[2] ^ (gfFactor[3] ^ copy[3]));
    output[3] = (byte)((gfFactor[0] ^ copy[0]) ^ copy[1] ^ copy[2] ^ gfFactor[3]);
    return output;
  }

  /**
   *
   * aes method for single block encryption.
   *
   * @param pTextHex: The input plaintext.
   * @param keyHex: The input key for AES.
   *
   * @return String: The string form of the single block ciphertext.
   */
  public String aes(String pTextHex, String keyHex) {
    String output = "";
    aesRoundKeys(keyHex);
    int index = 0;
    int count = 0;
    for(int i = 0; i < pTextHex.length()-1; i+=2) {
      stateMatrix[index][count%4] = (byte)((stringToByte(pTextHex.substring(i,i+1)) * 16) +
                                stringToByte(pTextHex.substring(i+1,i+2)));
      count++;
      if(count%4 == 0 && count != 0) {
        index++;
      }
    }
    int WMatrixColumn = 0;
    for(int round = 0; round < 9; round++) {
      int keyColumn = 0;
      while(keyColumn < 4) {
        int keyRow = 0;
        while(keyRow < 4) {
          keyInXOR[keyColumn][keyRow] =
            (byte)((stringToByte(WMatrix[keyRow][WMatrixColumn].substring(0,1)) * 16) +
                    stringToByte(WMatrix[keyRow][WMatrixColumn].substring(1,2)));
          keyRow++;
        }
        keyColumn++;
        WMatrixColumn++;
      }
      stateMatrix = aesStateXOR(stateMatrix,keyInXOR);
      stateMatrix = aesNibbleSub(stateMatrix);
      stateMatrix = aesShiftRow(stateMatrix);
      stateMatrix = aesMixColumn(stateMatrix);
    }
    int keyColumn = 0;
    while(keyColumn < 4) {
      int keyRow = 0;
      while(keyRow < 4) {
        keyInXOR[keyColumn][keyRow] =
          (byte)((stringToByte(WMatrix[keyRow][WMatrixColumn].substring(0,1)) * 16) +
                  stringToByte(WMatrix[keyRow][WMatrixColumn].substring(1,2)));
        keyRow++;
      }
      keyColumn++;
      WMatrixColumn++;
    }
    stateMatrix = aesStateXOR(stateMatrix, keyInXOR);
    stateMatrix = aesNibbleSub(stateMatrix);
    stateMatrix = aesShiftRow(stateMatrix);
    keyColumn = 0;
    while(keyColumn < 4) {
      int keyRow = 0;
      while(keyRow < 4) {
        keyInXOR[keyColumn][keyRow] =
          (byte)((stringToByte(WMatrix[keyRow][WMatrixColumn].substring(0,1)) * 16) +
                stringToByte(WMatrix[keyRow][WMatrixColumn].substring(1,2)));
        keyRow++;
      }
      keyColumn++;
      WMatrixColumn++;
    }
    stateMatrix = aesStateXOR(stateMatrix,keyInXOR);
    for(int i = 0; i < 4; i++) {
      for(int j = 0; j < 4; j++) {
        if(stateMatrix[i][j] < 16) {
          output += "0" + Integer.toHexString(stateMatrix[i][j]);
        } else {
          output += Integer.toHexString(stateMatrix[i][j]);
        }
      }
    }
    return output;
  }

  /**
   *
   * stringToByte method converts a hex string pair to a Byte.
   *
   * @param toByte: The hex string pair.
   *
   * @return byte: The byte value of the input string.
   */
  private byte stringToByte(String toByte) {
    return Byte.parseByte(toByte,16);
  }
}
