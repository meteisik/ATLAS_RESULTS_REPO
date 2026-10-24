import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V2_LunarComet {
    private static boolean privateReturnsTrue() { return true; }

    public void openLunarComet() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("LUNAR_COMET_PATH");
        } else {
            data = null;
        }
        String lunarCometRoot = "/home/user/uploads/";
        if (data != null) {
            File lunarCometFile = new File(lunarCometRoot + data);
            FileInputStream lunarCometStream = null;
            InputStreamReader lunarCometStreamReader = null;
            BufferedReader lunarCometReader = null;
            if (lunarCometFile.exists() && lunarCometFile.isFile()) {
                try {
                    lunarCometStream = new FileInputStream(lunarCometFile);
                    lunarCometStreamReader = new InputStreamReader(lunarCometStream, "UTF-8");
                    lunarCometReader = new BufferedReader(lunarCometStreamReader);
                    System.out.println(lunarCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V2_LunarComet").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (lunarCometReader != null) {
                            lunarCometReader.close();
                        }
                        if (lunarCometStreamReader != null) {
                            lunarCometStreamReader.close();
                        }
                        if (lunarCometStream != null) {
                            lunarCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V2_LunarComet").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
