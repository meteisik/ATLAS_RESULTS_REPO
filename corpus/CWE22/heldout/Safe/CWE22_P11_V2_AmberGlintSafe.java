import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AmberGlintSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openAmberGlint() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AmberGlintSafeSink()).readAmberGlint(dataHashMap);
    }
}

class CWE22_P11_V2_AmberGlintSafeSink {
    public void readAmberGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String amberGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File amberGlintFile = new File(amberGlintRoot + data);
            FileInputStream amberGlintStream = null;
            InputStreamReader amberGlintStreamReader = null;
            BufferedReader amberGlintReader = null;
            if (amberGlintFile.exists() && amberGlintFile.isFile()) {
                try {
                    amberGlintStream = new FileInputStream(amberGlintFile);
                    amberGlintStreamReader = new InputStreamReader(amberGlintStream, "UTF-8");
                    amberGlintReader = new BufferedReader(amberGlintStreamReader);
                    System.out.println(amberGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_AmberGlintSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberGlintReader != null) {
                            amberGlintReader.close();
                        }
                        if (amberGlintStreamReader != null) {
                            amberGlintStreamReader.close();
                        }
                        if (amberGlintStream != null) {
                            amberGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_AmberGlintSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
