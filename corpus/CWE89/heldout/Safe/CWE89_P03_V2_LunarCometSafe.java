import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_LunarCometSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void queryLunarComet(String data) throws SQLException {
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

    public void runLunarComet() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        queryLunarComet(data);
    }
}
