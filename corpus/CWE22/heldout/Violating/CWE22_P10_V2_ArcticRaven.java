import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ArcticRaven {
    public static String data;

    public void openArcticRaven() {
        if (5 == 5) {
            data = System.getenv("ARCTIC_RAVEN_PATH");
        } else {
            data = null;
        }
        (new CWE22_P10_V2_ArcticRavenSink()).readArcticRaven();
    }
}

class CWE22_P10_V2_ArcticRavenSink {
    public void readArcticRaven() {
        String data = CWE22_P10_V2_ArcticRaven.data;
        String arcticRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticRavenFile = new File(arcticRavenRoot + data);
            FileInputStream arcticRavenStream = null;
            InputStreamReader arcticRavenStreamReader = null;
            BufferedReader arcticRavenReader = null;
            if (arcticRavenFile.exists() && arcticRavenFile.isFile()) {
                try {
                    arcticRavenStream = new FileInputStream(arcticRavenFile);
                    arcticRavenStreamReader = new InputStreamReader(arcticRavenStream, "UTF-8");
                    arcticRavenReader = new BufferedReader(arcticRavenStreamReader);
                    System.out.println(arcticRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ArcticRavenSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticRavenReader != null) {
                            arcticRavenReader.close();
                        }
                        if (arcticRavenStreamReader != null) {
                            arcticRavenStreamReader.close();
                        }
                        if (arcticRavenStream != null) {
                            arcticRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ArcticRavenSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
