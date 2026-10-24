import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_LunarComet {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runLunarComet() throws SQLException {
        String dataCopy;
        {
            String data;
            if (IO.staticTrue) {
                data = System.getenv("LUNAR_COMET_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection lunarCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarComet");
            Statement lunarCometStatement = null;
            ResultSet lunarCometRows = null;
            try {
                lunarCometStatement = lunarCometConnection.createStatement();
                lunarCometRows = lunarCometStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(lunarCometRows.getRow());
            } finally {
                if (lunarCometRows != null) {
                    lunarCometRows.close();
                }
                if (lunarCometStatement != null) {
                    lunarCometStatement.close();
                }
                lunarCometConnection.close();
            }
        }
    }
}
