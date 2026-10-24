import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_ArcticRavenSafe {
    private static int privateFive = 5;

    public void openArcticRaven() {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_ArcticRavenSafeBase baseObject = new CWE22_P12_V2_ArcticRavenSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_ArcticRavenSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_ArcticRavenSafeSink extends CWE22_P12_V2_ArcticRavenSafeBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V2_ArcticRavenSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V2_ArcticRavenSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
