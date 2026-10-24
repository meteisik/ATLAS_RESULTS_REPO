import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_SaffronGlint {
    public static String data;

    public void openSaffronGlint() {
        data = System.getenv("SAFFRON_GLINT_PATH");
        (new CWE22_P10_V1_SaffronGlintSink()).readSaffronGlint();
    }
}

class CWE22_P10_V1_SaffronGlintSink {
    public void readSaffronGlint() {
        String data = CWE22_P10_V1_SaffronGlint.data;
        String saffronGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronGlintFile = new File(saffronGlintRoot + data);
            FileInputStream saffronGlintStream = null;
            InputStreamReader saffronGlintStreamReader = null;
            BufferedReader saffronGlintReader = null;
            if (saffronGlintFile.exists() && saffronGlintFile.isFile()) {
                try {
                    saffronGlintStream = new FileInputStream(saffronGlintFile);
                    saffronGlintStreamReader = new InputStreamReader(saffronGlintStream, "UTF-8");
                    saffronGlintReader = new BufferedReader(saffronGlintStreamReader);
                    System.out.println(saffronGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V1_SaffronGlintSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronGlintReader != null) {
                            saffronGlintReader.close();
                        }
                        if (saffronGlintStreamReader != null) {
                            saffronGlintStreamReader.close();
                        }
                        if (saffronGlintStream != null) {
                            saffronGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V1_SaffronGlintSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
