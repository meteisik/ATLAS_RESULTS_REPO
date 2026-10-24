import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_GoldenGlint {
    private static int privateFive = 5;

    public void openGoldenGlint() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("GOLDEN_GLINT_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_GoldenGlintBase baseObject = new CWE22_P12_V2_GoldenGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_GoldenGlintBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_GoldenGlintSink extends CWE22_P12_V2_GoldenGlintBase {
    public void action(String data) {
        String goldenGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenGlintFile = new File(goldenGlintRoot + data);
            FileInputStream goldenGlintStream = null;
            InputStreamReader goldenGlintStreamReader = null;
            BufferedReader goldenGlintReader = null;
            if (goldenGlintFile.exists() && goldenGlintFile.isFile()) {
                try {
                    goldenGlintStream = new FileInputStream(goldenGlintFile);
                    goldenGlintStreamReader = new InputStreamReader(goldenGlintStream, "UTF-8");
                    goldenGlintReader = new BufferedReader(goldenGlintStreamReader);
                    System.out.println(goldenGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_GoldenGlintSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenGlintReader != null) {
                            goldenGlintReader.close();
                        }
                        if (goldenGlintStreamReader != null) {
                            goldenGlintStreamReader.close();
                        }
                        if (goldenGlintStream != null) {
                            goldenGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_GoldenGlintSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
