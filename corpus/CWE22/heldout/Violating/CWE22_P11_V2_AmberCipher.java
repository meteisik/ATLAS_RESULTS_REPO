import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AmberCipher {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void openAmberCipher() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_CIPHER_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AmberCipherSink()).readAmberCipher(dataHashMap);
    }
}

class CWE22_P11_V2_AmberCipherSink {
    public void readAmberCipher(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String amberCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File amberCipherFile = new File(amberCipherRoot + data);
            FileInputStream amberCipherStream = null;
            InputStreamReader amberCipherStreamReader = null;
            BufferedReader amberCipherReader = null;
            if (amberCipherFile.exists() && amberCipherFile.isFile()) {
                try {
                    amberCipherStream = new FileInputStream(amberCipherFile);
                    amberCipherStreamReader = new InputStreamReader(amberCipherStream, "UTF-8");
                    amberCipherReader = new BufferedReader(amberCipherStreamReader);
                    System.out.println(amberCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_AmberCipherSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberCipherReader != null) {
                            amberCipherReader.close();
                        }
                        if (amberCipherStreamReader != null) {
                            amberCipherStreamReader.close();
                        }
                        if (amberCipherStream != null) {
                            amberCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_AmberCipherSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
