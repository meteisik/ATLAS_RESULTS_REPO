import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CobaltRavenSafe {
    private static int privateFive = 5;

    public void openCobaltRaven() {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_CobaltRavenSafeBase baseObject = new CWE22_P12_V2_CobaltRavenSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CobaltRavenSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CobaltRavenSafeSink extends CWE22_P12_V2_CobaltRavenSafeBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V2_CobaltRavenSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V2_CobaltRavenSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
