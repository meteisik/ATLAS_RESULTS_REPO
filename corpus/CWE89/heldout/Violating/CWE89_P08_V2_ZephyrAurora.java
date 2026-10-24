import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_ZephyrAurora {

    public void runZephyrAurora() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ZEPHYR_AURORA_FILTER");
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_ZephyrAuroraSink()).queryZephyrAurora(dataArray);
    }
}

class CWE89_P08_V2_ZephyrAuroraSink {
    public void queryZephyrAurora(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection zephyrAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrAurora");
        Statement zephyrAuroraStatement = null;
        ResultSet zephyrAuroraRows = null;
        try {
            zephyrAuroraStatement = zephyrAuroraConnection.createStatement();
            zephyrAuroraRows = zephyrAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrAuroraRows.getRow());
        } finally {
            if (zephyrAuroraRows != null) {
                zephyrAuroraRows.close();
            }
            if (zephyrAuroraStatement != null) {
                zephyrAuroraStatement.close();
            }
            zephyrAuroraConnection.close();
        }
    }
}
