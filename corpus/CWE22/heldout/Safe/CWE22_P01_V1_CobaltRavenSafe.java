import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V1_CobaltRavenSafe {

    public void openCobaltRaven() {
        String data;
        data = "foo";
        String cobaltRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File cobaltRavenFile = new File(cobaltRavenRoot + data);
            FileInputStream cobaltRavenStream = null;
            InputStreamReader cobaltRavenStreamReader = null;
            BufferedReader cobaltRavenReader = null;
            if (cobaltRavenFile.exists() && cobaltRavenFile.isFile()) {
                try {
                    cobaltRavenStream = new FileInputStream(cobaltRavenFile);
                    cobaltRavenStreamReader = new InputStreamReader(cobaltRavenStream, "UTF-8");
                    cobaltRavenReader = new BufferedReader(cobaltRavenStreamReader);
                    System.out.println(cobaltRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V1_CobaltRavenSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (cobaltRavenReader != null) {
                            cobaltRavenReader.close();
                        }
                        if (cobaltRavenStreamReader != null) {
                            cobaltRavenStreamReader.close();
                        }
                        if (cobaltRavenStream != null) {
                            cobaltRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V1_CobaltRavenSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
