import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_LunarHelix {

    private String locateLunarHelix() {
        String data;
        data = System.getenv("LUNAR_HELIX_PATH");
        return data;
    }

    public void openLunarHelix() {
        String data = locateLunarHelix();
        String lunarHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File lunarHelixFile = new File(lunarHelixRoot + data);
            FileInputStream lunarHelixStream = null;
            InputStreamReader lunarHelixStreamReader = null;
            BufferedReader lunarHelixReader = null;
            if (lunarHelixFile.exists() && lunarHelixFile.isFile()) {
                try {
                    lunarHelixStream = new FileInputStream(lunarHelixFile);
                    lunarHelixStreamReader = new InputStreamReader(lunarHelixStream, "UTF-8");
                    lunarHelixReader = new BufferedReader(lunarHelixStreamReader);
                    System.out.println(lunarHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V1_LunarHelix").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (lunarHelixReader != null) {
                            lunarHelixReader.close();
                        }
                        if (lunarHelixStreamReader != null) {
                            lunarHelixStreamReader.close();
                        }
                        if (lunarHelixStream != null) {
                            lunarHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V1_LunarHelix").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
