import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_LunarHelixSafe {

    private String lunarHelixData;

    private void queryLunarHelix() throws SQLException {
        String data = lunarHelixData;
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

    public void runLunarHelix() throws SQLException {
        String data;
        data = "foo";
        lunarHelixData = data;
        queryLunarHelix();
    }
}
