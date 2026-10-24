import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_LunarNebula {

    private void queryLunarNebula(String data) throws SQLException {
        Connection lunarNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarNebula");
        Statement lunarNebulaStatement = null;
        ResultSet lunarNebulaRows = null;
        try {
            lunarNebulaStatement = lunarNebulaConnection.createStatement();
            lunarNebulaRows = lunarNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(lunarNebulaRows.getRow());
        } finally {
            if (lunarNebulaRows != null) {
                lunarNebulaRows.close();
            }
            if (lunarNebulaStatement != null) {
                lunarNebulaStatement.close();
            }
            lunarNebulaConnection.close();
        }
    }

    public void runLunarNebula() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("LUNAR_NEBULA_FILTER");
            break;
        default:
            data = null;
            break;
        }
        queryLunarNebula(data);
    }
}
