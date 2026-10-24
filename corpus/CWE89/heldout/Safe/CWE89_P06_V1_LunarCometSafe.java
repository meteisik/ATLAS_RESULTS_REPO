import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_LunarCometSafe {

    public void runLunarComet() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_LunarCometSafeSink()).queryLunarComet(data);
    }
}

class CWE89_P06_V1_LunarCometSafeSink {
    public void queryLunarComet(String data) throws SQLException {
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
