import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_GoldenCascade {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void openGoldenCascade() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("GOLDEN_CASCADE_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_GoldenCascadeBase baseObject = new CWE22_P12_V2_GoldenCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_GoldenCascadeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_GoldenCascadeSink extends CWE22_P12_V2_GoldenCascadeBase {
    public void action(String data) {
        String goldenCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenCascadeFile = new File(goldenCascadeRoot + data);
            FileInputStream goldenCascadeStream = null;
            InputStreamReader goldenCascadeStreamReader = null;
            BufferedReader goldenCascadeReader = null;
            if (goldenCascadeFile.exists() && goldenCascadeFile.isFile()) {
                try {
                    goldenCascadeStream = new FileInputStream(goldenCascadeFile);
                    goldenCascadeStreamReader = new InputStreamReader(goldenCascadeStream, "UTF-8");
                    goldenCascadeReader = new BufferedReader(goldenCascadeStreamReader);
                    System.out.println(goldenCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_GoldenCascadeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenCascadeReader != null) {
                            goldenCascadeReader.close();
                        }
                        if (goldenCascadeStreamReader != null) {
                            goldenCascadeStreamReader.close();
                        }
                        if (goldenCascadeStream != null) {
                            goldenCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_GoldenCascadeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
