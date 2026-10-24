import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_AmberGlintSafe {
    public static String data;
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void openAmberGlint() {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P10_V2_AmberGlintSafeSink()).readAmberGlint();
    }
}

class CWE22_P10_V2_AmberGlintSafeSink {
    public void readAmberGlint() {
        String data = CWE22_P10_V2_AmberGlintSafe.data;
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
                    Logger.getLogger("CWE22_P10_V2_AmberGlintSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P10_V2_AmberGlintSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
