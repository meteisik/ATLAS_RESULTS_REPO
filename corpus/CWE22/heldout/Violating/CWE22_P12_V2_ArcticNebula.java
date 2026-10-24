import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_ArcticNebula {
    private static boolean privateTrue = true;

    public void openArcticNebula() {
        String data;
        if (privateTrue) {
            data = System.getenv("ARCTIC_NEBULA_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_ArcticNebulaBase baseObject = new CWE22_P12_V2_ArcticNebulaSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_ArcticNebulaBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_ArcticNebulaSink extends CWE22_P12_V2_ArcticNebulaBase {
    public void action(String data) {
        String arcticNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticNebulaFile = new File(arcticNebulaRoot + data);
            FileInputStream arcticNebulaStream = null;
            InputStreamReader arcticNebulaStreamReader = null;
            BufferedReader arcticNebulaReader = null;
            if (arcticNebulaFile.exists() && arcticNebulaFile.isFile()) {
                try {
                    arcticNebulaStream = new FileInputStream(arcticNebulaFile);
                    arcticNebulaStreamReader = new InputStreamReader(arcticNebulaStream, "UTF-8");
                    arcticNebulaReader = new BufferedReader(arcticNebulaStreamReader);
                    System.out.println(arcticNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_ArcticNebulaSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticNebulaReader != null) {
                            arcticNebulaReader.close();
                        }
                        if (arcticNebulaStreamReader != null) {
                            arcticNebulaStreamReader.close();
                        }
                        if (arcticNebulaStream != null) {
                            arcticNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_ArcticNebulaSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
