import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_GoldenFlare {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openGoldenFlare() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("GOLDEN_FLARE_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_GoldenFlareBase baseObject = new CWE22_P12_V2_GoldenFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_GoldenFlareBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_GoldenFlareSink extends CWE22_P12_V2_GoldenFlareBase {
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
                    Logger.getLogger("CWE22_P12_V2_GoldenFlareSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V2_GoldenFlareSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
