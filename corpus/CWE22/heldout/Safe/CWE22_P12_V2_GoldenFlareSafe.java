import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_GoldenFlareSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openGoldenFlare() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_GoldenFlareSafeBase baseObject = new CWE22_P12_V2_GoldenFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_GoldenFlareSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_GoldenFlareSafeSink extends CWE22_P12_V2_GoldenFlareSafeBase {
    public void action(String data) {
        String goldenFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenFlareFile = new File(goldenFlareRoot + data);
            FileInputStream goldenFlareStream = null;
            InputStreamReader goldenFlareStreamReader = null;
            BufferedReader goldenFlareReader = null;
            if (goldenFlareFile.exists() && goldenFlareFile.isFile()) {
                try {
                    goldenFlareStream = new FileInputStream(goldenFlareFile);
                    goldenFlareStreamReader = new InputStreamReader(goldenFlareStream, "UTF-8");
                    goldenFlareReader = new BufferedReader(goldenFlareStreamReader);
                    System.out.println(goldenFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_GoldenFlareSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenFlareReader != null) {
                            goldenFlareReader.close();
                        }
                        if (goldenFlareStreamReader != null) {
                            goldenFlareStreamReader.close();
                        }
                        if (goldenFlareStream != null) {
                            goldenFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_GoldenFlareSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
