package Security;

import java.util.*;

public class MonoalphabeticCipher {

    public String analyse(String plainText, String cipherText) {
        cipherText = cipherText.toLowerCase();
        plainText = plainText.toLowerCase();
        char[] key = new char[26];

        // Initialize with null characters
        Arrays.fill(key, '\0');

        // Map existing characters from plain to cipher
        for (int i = 0; i < plainText.length(); i++) {
            int m = plainText.charAt(i) - 'a';
            key[m] = cipherText.charAt(i);
        }

        // Fill remaining empty spots in the key with unused letters
        for (int i = 0; i < 26; i++) {
            if (key[i] == '\0') {
                for (int j = 0; j < 26; j++) {
                    char c = (char) (j + 'a');
                    boolean found = false;
                    for (int k = 0; k < 26; k++) {
                        if (key[k] == c) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        key[i] = c;
                        break;
                    }
                }
            }
        }
        return new String(key);
    }

    public String decrypt(String cipherText, String key) {
        cipherText = cipherText.toLowerCase();
        key = key.toLowerCase();
        StringBuilder plainText = new StringBuilder();

        for (int i = 0; i < cipherText.length(); i++) {
            char letter = cipherText.charAt(i);
            int j = key.indexOf(letter);

            if (j != -1) {
                char l = (char) (j + 'a');
                plainText.append(l);
            }
        }
        return plainText.toString();
    }

    public String encrypt(String plainText, String key) {
        plainText = plainText.toLowerCase();
        key = key.toLowerCase();
        StringBuilder ciphertext = new StringBuilder();

        for (int i = 0; i < plainText.length(); i++) {
            int index = plainText.charAt(i) - 'a';
            ciphertext.append(key.charAt(index));
        }
        return ciphertext.toString();
    }


    /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
    public String analyseUsingCharFrequency(String cipher) {
        cipher = cipher.toUpperCase();

        // English letter frequencies for scoring
        double[] englishFreq = {
                8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
                6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
                0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
                1.974, 0.074
        };

        int[] freq = new int[26];
        int total = 0;
        for (char c : cipher.toCharArray()) {
            if (c >= 'A' && c <= 'Z') {
                freq[c - 'A']++;
                total++;
            }
        }

        int bestShift = 0;
        double bestScore = Double.NEGATIVE_INFINITY;

        for (int shift = 0; shift < 26; shift++) {
            double score = 0;
            for (int i = 0; i < 26; i++) {
                int plainIndex = (i - shift + 26) % 26;
                score += (freq[i] * 1.0 / total) * englishFreq[plainIndex];
            }
            if (score > bestScore) {
                bestScore = score;
                bestShift = shift;
            }
        }

        String result = "";
        for (char c : cipher.toCharArray()) {
            if (c >= 'A' && c <= 'Z') {
                result += (char) (((c - 'A' - bestShift + 26) % 26) + 'A');
            } else {
                result += c;
            }
        }
        return result.toLowerCase();
    }
}
