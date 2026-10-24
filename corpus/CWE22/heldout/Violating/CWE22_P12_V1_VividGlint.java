import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_VividGlint {

    public void openVividGlint() {
        String data;
        data = System.getenv("VIVID_GLINT_PATH");
        CWE22_P12_V1_VividGlintBase baseObject = new CWE22_P12_V1_VividGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_VividGlintBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_VividGlintSink extends CWE22_P12_V1_VividGlintBase {
    public void action(String data) {
        String vividGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File vividGlintFile = new File(vividGlintRoot + data);
            FileInputStream vividGlintStream = null;
            InputStreamReader vividGlintStreamReader = null;
            BufferedReader vividGlintReader = null;
            if (vividGlintFile.exists() && vividGlintFile.isFile()) {
                try {
                    vividGlintStream = new FileInputStream(vividGlintFile);
                    vividGlintStreamReader = new InputStreamReader(vividGlintStream, "UTF-8");
                    vividGlintReader = new BufferedReader(vividGlintStreamReader);
                    System.out.println(vividGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_VividGlintSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividGlintReader != null) {
                            vividGlintReader.close();
                        }
                        if (vividGlintStreamReader != null) {
                            vividGlintStreamReader.close();
                        }
                        if (vividGlintStream != null) {
                            vividGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_VividGlintSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
