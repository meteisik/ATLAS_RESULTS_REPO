import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_LunarComet {

    public void runLunarComet() throws SQLException {
        String data;
        data = System.getenv("LUNAR_COMET_FILTER");
        (new CWE89_P06_V1_LunarCometSink()).queryLunarComet(data);
    }
}

class CWE89_P06_V1_LunarCometSink {
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
