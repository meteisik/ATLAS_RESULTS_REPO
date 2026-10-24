import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_LunarComet {
    private static boolean privateReturnsTrue() { return true; }

    public void runLunarComet() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("LUNAR_COMET_FILTER");
        } else {
            data = null;
        }
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
