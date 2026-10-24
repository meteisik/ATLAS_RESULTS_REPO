import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_LunarHelixSafe {

    public void runLunarHelix() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_LunarHelixSafeSink()).queryLunarHelix(data);
    }
}

class CWE89_P06_V1_LunarHelixSafeSink {
    public void queryLunarHelix(String data) throws SQLException {
        Connection lunarHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarHelix");
        Statement lunarHelixStatement = null;
        ResultSet lunarHelixRows = null;
        try {
            lunarHelixStatement = lunarHelixConnection.createStatement();
            lunarHelixRows = lunarHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(lunarHelixRows.getRow());
        } finally {
            if (lunarHelixRows != null) {
                lunarHelixRows.close();
            }
            if (lunarHelixStatement != null) {
                lunarHelixStatement.close();
            }
            lunarHelixConnection.close();
        }
    }
}
