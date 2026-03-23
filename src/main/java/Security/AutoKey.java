package Security;

public class AutoKey {
    public String decrypt(String text, String key){
        text = text.toUpperCase();
        String currentKey = key.toUpperCase();
        String result = "";
        int keyIndex = 0;

        for(int i = 0; i < text.length(); i++){
            char currentChar = text.charAt(i);
            if(currentChar >= 'A' && currentChar <= 'Z'){
                char dec = (char)(((currentChar - currentKey.charAt(keyIndex) + 26)%26)+ 'A');
                result += dec;
                currentKey += dec;
                keyIndex++;
            } else {
                result += currentChar;
            }
        }
        return result.toLowerCase();
    }

    public String analyse(String plainText, String cipherText) {
        plainText = plainText.toUpperCase().replaceAll("[^A-Z]", "");
        cipherText = cipherText.toUpperCase().replaceAll("[^A-Z]", "");

        if (plainText.isEmpty()) return "";

        String key = "";
        for (int i = 0; i < plainText.length(); i++) {
            char keyChar = (char) (((cipherText.charAt(i) - plainText.charAt(i) + 26) % 26) + 'A');
            key += keyChar;
        }

        for(int i = 1; i <= key.length(); i++){
            String sub = key.substring(0, i);
            if(key.substring(i).equals(plainText.substring(0, key.length() - i))){
                return sub.toLowerCase();
            }
        }

        return key.toLowerCase();
    }
}
