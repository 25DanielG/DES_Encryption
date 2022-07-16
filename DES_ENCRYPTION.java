import java.util.Scanner;
public class DES_ENCRYPTION {
	// all standard permutation tables and bit rotation arrays gotten from
	// http://orion.towson.edu/~mzimand/cryptostuff/DES-tables.pdf
	
	private static final byte[] IP = { // IP
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7};
	
	private static final byte[] PC1 = { // PC1
		57, 49, 41, 33, 25, 17, 9,
		1,  58, 50, 42, 34, 26, 18,
		10, 2,  59, 51, 43, 35, 27,
		19, 11, 3,  60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7,  62, 54, 46, 38, 30, 22,
		14, 6,  61, 53, 45, 37, 29,
		21, 13, 5,  28, 20, 12, 4};

	private static final byte[] PC2 = { // PC2
		14, 17, 11, 24, 1,  5,
		3, 28, 15, 6,  21, 10,
		23, 19, 12, 4,  26, 8,
		16, 7,  27, 20, 13, 2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32};

	private static final byte[] E = { // Expand Arr
		32, 1,  2,  3,  4,  5,
		4,  5,  6,  7,  8,  9,
		8,  9,  10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1};

	private static final byte[] P = { // Permute Arr
		16, 7,  20, 21,
		29, 12, 28, 17,
		1,  15, 23, 26,
		5,  18, 31, 10,
		2,  8,  24, 14,
		32, 27, 3,  9,
		19, 13, 30, 6,
		22, 11, 4,  25};
	
	private static final byte[][] S = {{ // Subst Arr
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}, {
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}, {
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}, {
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7,  2, 14}, {
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}, {
		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}, {
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}, {
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};
	
	private static final byte[] FP = { // FP
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25};

	private static final byte[] bitRotationArr = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}; // Rot Arr
	private static int[] xHalf = new int[28]; // for updatedCArr halves
	private static int[] yHalf = new int[28];
	private static int[][] subkey = new int[16][48]; // subkeys
	
	public static void main(String args[]) {
		String messageToEncrypt = "What an L bozo moment.";
		StringBuilder strBuild = new StringBuilder();
		String text = "";
        char[] cArr = messageToEncrypt.toCharArray();
        for (char c : cArr) {
            text = Integer.toHexString(c);
            strBuild.append(text);
        }
		text = strBuild.toString();
		int textMoupdatedDArr6 = text.length() % 16;
		int numPaddingAdded = 16 - textMoupdatedDArr6;
		if(textMoupdatedDArr6 != 0) {
			for(int i = 0; i < 16 - textMoupdatedDArr6; ++i) {
				text += 0;
			}
		}
		int numSequences = text.length() / 16;
		String[] diffTexts = new String[numSequences];
		for(int i = 0; i < numSequences; ++i) {
			diffTexts[i] = text.substring(i * 16, (i + 1) * 16); // Making an array of 16 bit hex strings (DES algorithm requirement)
		}
		int[][] stringBitArr = new int[numSequences][64]; // stores multiple hex strings of 16 bits
		for(int n = 0; n < numSequences; ++n) {
			for(int i = 0; i < 16; ++i) {
				String str = Integer.toBinaryString(Integer.parseInt(diffTexts[n].charAt(i) + "", 16));
				// padding zeroes
				str = addPadding(str);
				for(int j = 0; j < 4; ++j) {
					String jChar = str.charAt(j) + "";
					stringBitArr[n][(4 * i) + j] = Integer.parseInt(jChar);
				}
			}
		}
		String mainKey = "b47e9c0e3029d489";
		int keyBitArr[] = new int[64];
		for(int i = 0; i < 16; ++i) {
			int tmp = Integer.parseInt(mainKey.charAt(i) + "", 16);
			String s = addPadding(Integer.toBinaryString(tmp));
			for(int j = 0; j < 4; ++j) {
				keyBitArr[(4 * i) + j] = Integer.parseInt(s.charAt(j) + "");
			}
		}
		System.out.println("\nENCRYPTED TEXT\n--------------");
		int[][] outArr = new int[numSequences][]; // calls encryption
		for(int i = 0; i < numSequences; ++i) {
			outArr[i] = encryptMessage(stringBitArr[i], keyBitArr);
		}
		System.out.println();
		System.out.println("\nDECRYPTED TEXT\n--------------");
		for(int i = 0; i < numSequences; ++i) { // call decryption
			decryptMessage(outArr[i], keyBitArr, numPaddingAdded);
		}
		System.out.println();
		System.out.println();
	}
	
	private static int[] encryptMessage(int[] stringBitArr, int[] keyBitArr) {
		// Use IP
		int updatedArr[] = new int[stringBitArr.length];
		for(int i = 0; i < stringBitArr.length; ++i) {
			updatedArr[i] = stringBitArr[IP[i] - 1];
		}
		// left and right halves
		int left[] = new int[32];
		int right[] = new int[32];
		// Use PC1
		for(int i = 0; i < 28; ++i) {
			xHalf[i] = keyBitArr[PC1[i] - 1];
		}
		for(int i = 28; i < 56; ++i) {
			yHalf[i - 28] = keyBitArr[PC1[i] - 1];
		}
		// l & r -> fiestel
		for(int i = 0; i < 32; ++i) {
			left[i] = updatedArr[i];
		}
		for(int i = 0; i < 32; ++i) {
			right[i] = updatedArr[i + 32];
		}
		for(int n = 0; n < 16; ++n) {
			// right genned by fiestel. Generate subkey.
			int fiestelRight[];
			fiestelRight = fiestelFunction(right, KeyGen(n, keyBitArr));
			// a ^ b = c | c ^ b = a
			int updatedLeft[] = xorAddition(left, fiestelRight);
			left = right;
			right = updatedLeft;
		}
		int output[] = new int[64];
		for(int i = 0; i < 32; ++i) {
			output[i] = right[i];
		}
		for(int i = 0; i < 32; ++i) {
			output[i + 32] = left[i];
		}
		int ret[] = new int[64];
		// Use FP
		for(int i = 0; i < 64; ++i) {
			ret[i] = output[FP[i] - 1];
		}
		
		// make into hex string
		String hex = new String();
		for(int i = 0; i < 16; ++i) {
			String tmp = new String();
			for(int j = 0; j < 4; ++j) {
				tmp += ret[(4 * i) + j];
			}
			int decimal = Integer.parseInt(tmp, 2);
			hex += Integer.toHexString(decimal);
		}
		// convert hex string to all capital
		String finalEncrypted = "";
		for(int i = 0; i < hex.length(); ++i) {
			int tmpASCII = hex.charAt(i);
			if(tmpASCII >= 97 && tmpASCII <= 122) {
				finalEncrypted += (char)(tmpASCII - 32);
			}
			else {
				finalEncrypted += hex.charAt(i);
			}
		}
		System.out.print(finalEncrypted);
		return ret;
	}
	private static int[] decryptMessage(int[] stringBitArr, int[] keyBitArr, int paddingAdded) {
		// Use IP
		int updatedArr[] = new int[stringBitArr.length];
		for(int i = 0; i < stringBitArr.length; ++i) {
			updatedArr[i] = stringBitArr[IP[i] - 1];
		}
		// left and right halves
		int left[] = new int[32];
		int right[] = new int[32];
		// Use PC1
		for(int i = 0; i < 28; ++i) {
			xHalf[i] = keyBitArr[PC1[i] - 1];
		}
		for(int i = 28; i < 56; ++i) {
			yHalf[i - 28] = keyBitArr[PC1[i] - 1];
		}
		// l & r -> fiestel
		for(int i = 0; i < 32; ++i) {
			left[i] = updatedArr[i];
		}
		for(int i = 0; i < 32; ++i) {
			right[i] = updatedArr[i + 32];
		}
		for(int i = 0; i < 32; ++i) {
			updatedArr[i] = left[i];
		}
		for(int i = 0; i < 32; ++i) {
			updatedArr[i + 32] = right[i];
		}
		// fiestal structure
		for(int n = 0; n < 16; ++n) {
			// right genned by fiestel. Generate subkey.
			int fiestelRight[] = new int[0];
			fiestelRight = fiestelFunction(right, subkey[15 - n]);
			// a ^ b = c | c ^ a = b
			int updatedLeft[] = xorAddition(left, fiestelRight);
			left = right;
			right = updatedLeft;
		}
		int output[] = new int[64];
		for(int i = 0; i < 32; ++i) {
			output[i] = right[i];
		}
		for(int i = 0; i < 32; ++i) {
			output[i + 32] = left[i];
		}
		int ret[] = new int[64];
		// Use FP
		for(int i = 0; i < 64; ++i) {
			ret[i] = output[FP[i] - 1];
		}
		// hex string
		String hex = new String();
		for(int i = 0; i < 16; ++i) {
			String tmp = new String();
			for(int j = 0; j < 4; ++j) {
				tmp += ret[(4 * i) + j];
			}
			int decimal = Integer.parseInt(tmp, 2);
			hex += Integer.toHexString(decimal);
		}
        String outStr = ""; // convert hex to normal string
        char[] tmpCharArr = hex.toCharArray();
        for(int x = 0; x < tmpCharArr.length; x += 2) {
            String tmp = "" + tmpCharArr[x] + "" + tmpCharArr[x + 1];
            char character = (char)Integer.parseInt(tmp, 16);
            outStr += character;
        }
		String encryptedSequence = "";
		for(int i = 0; i < outStr.length(); ++i) {
			encryptedSequence += (outStr.charAt(i) + "").toUpperCase();
		}
		System.out.print(outStr);
		return ret;
	}
	
	private static int[] fiestelFunction(int[] R, int[] roundKey) {
		// Use expand arr
		int expandedR[] = new int[48];
		for(int i = 0 ; i < 48 ; ++i) {
			expandedR[i] = R[E[i] - 1];
		}
		// expanded arr -> right (XOR) round key
		int arr[] = xorAddition(expandedR, roundKey);
		// Use SBOX
		int output[] = applySubBoxes(arr);
		return output;
	}
	
	private static int[] KeyGen(int rNum, int[] key) {
		// round keys to update C, D
		int updatedCArr[] = new int[28];
		int updatedDArr[] = new int[28];
		// num of bitRotationArr
		int rotationTimes = (int)(bitRotationArr[rNum]);
		//shift everything left
		updatedCArr = shiftItemsLeft(xHalf, rotationTimes);
		updatedDArr = shiftItemsLeft(yHalf, rotationTimes);
		// copy left and right arr into halfCD
		int halfCD[] = new int[56];
		for(int i = 0; i < 28; ++i) {
			halfCD[i] = updatedCArr[i];
		}
		for(int i = 0; i < 28; ++i) {
			halfCD[i + 28] = updatedDArr[i];
		}
		// subkey
		int subKeyCD[] = new int[48];
		for(int i = 0; i < subKeyCD.length; ++i) {
			subKeyCD[i] = halfCD[PC2[i] - 1];
		}
		// reset
		subkey[rNum] = subKeyCD;
		xHalf = updatedCArr;
		yHalf = updatedDArr;
		return subKeyCD;
	}

	private static int[] xorAddition(int[] a, int[] b) {
		// xorAddition two arrays
		int answer[] = new int[a.length];
		for(int i = 0; i < a.length; ++i) {
			answer[i] = a[i] ^ b[i];
		}
		return answer;
	}
	
	private static int[] applySubBoxes(int[] bits) { // substitution boxes
		int output[] = new int[32];
		// use subkeys
		String substiColumn, substiRow, s;
		int initialRow, initialColumn;
		for(int i = 0; i < 8; ++i) {
			int row[] = new int [2];
			int column[] = new int[4];
			row[0] = bits[6 * i];
			row[1] = bits[(6 * i) + 5];
			substiRow = row[0] + "" + row[1];
			column[0] = bits[(6 * i) + 1];
			column[1] = bits[(6 * i) + 2];
			column[2] = bits[(6 * i) + 3];
			column[3] = bits[(6 * i) + 4];
			substiColumn = column[0] + "" + column[1] + "" + column[2] + "" + column[3];
			// base 2 -> 10
			initialRow = Integer.parseInt(substiRow, 2);
			initialColumn = Integer.parseInt(substiColumn, 2);
			int x = S[i][(initialRow * 16) + initialColumn];
			// sbox base 10 -> 2
			s = Integer.toBinaryString(x);
			// add padding
			s = addPadding(s);
			// add result
			for(int j = 0; j < 4; ++j) {
				output[(i * 4) + j] = Integer.parseInt(s.charAt(j) + "");
			}
		}
		// Use permute table
		int ret[] = new int[32];
		for(int i = 0; i < 32; ++i) {
			ret[i] = output[P[i] - 1];
		}
		return ret;
	}
	
	private static int[] shiftItemsLeft(int[] items, int length) {
		int answer[] = new int[items.length];
		for(int i = 0; i < items.length; ++i) {
			answer[i] = items[i];
		}
		for(int i = 0; i < length; ++i) {
			int tmp = answer[0];
			for(int j = 0; j < items.length - 1; ++j) {
				answer[j] = answer[j + 1];
			}
			answer[items.length - 1] = tmp;
		}
		return answer;
	}
	private static String removeZeroPadding(String str, int numPadding) {
		String unPaddedArr = "";
		for(int i = 0; i < str.length() - numPadding; ++i) {
			unPaddedArr += str.charAt(i);
		}
		return unPaddedArr;
	}
	private static String addPadding(String str) {
		while(str.length() < 4) {
			str = "0" + str;
		}
		return str;
	}
}
