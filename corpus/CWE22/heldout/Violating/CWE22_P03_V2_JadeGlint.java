import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V2_JadeGlint {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private void readJadeGlint(String data) {
        String jadeGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeGlintFile = new File(jadeGlintRoot + data);
            FileInputStream jadeGlintStream = null;
            InputStreamReader jadeGlintStreamReader = null;
            BufferedReader jadeGlintReader = null;
            if (jadeGlintFile.exists() && jadeGlintFile.isFile()) {
                try {
                    jadeGlintStream = new FileInputStream(jadeGlintFile);
                    jadeGlintStreamReader = new InputStreamReader(jadeGlintStream, "UTF-8");
                    jadeGlintReader = new BufferedReader(jadeGlintStreamReader);
                    System.out.println(jadeGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V2_JadeGlint").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeGlintReader != null) {
                            jadeGlintReader.close();
                        }
                        if (jadeGlintStreamReader != null) {
                            jadeGlintStreamReader.close();
                        }
                        if (jadeGlintStream != null) {
                            jadeGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V2_JadeGlint").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openJadeGlint() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("JADE_GLINT_PATH");
        } else {
            data = null;
        }
        readJadeGlint(data);
    }
}
